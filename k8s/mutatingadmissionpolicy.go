// Copyright 2025 Undistro Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	jsonpatch "gopkg.in/evanphx/json-patch.v4"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"
	celplugin "k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/admission/plugin/policy/mutating/patch"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/cel/environment"
	sigsyaml "sigs.k8s.io/yaml"
)

// Inputs that make mutation impossible. They are reported against each mutation
// rather than failing the whole evaluation, so the matchCondition results the
// user did get are still rendered.
var (
	errNoObject    = errors.New("a mutation needs something to mutate: paste the object the policy acts on into the Object tab")
	errNoObjectGVK = errors.New("the object must set apiVersion and kind before it can be mutated")
)

// maxMutatedObjectBytes is the largest object a mutation may produce. A cluster
// stores an object in etcd, which refuses one much past a megabyte -- the same
// ceiling a ConfigMap's data runs into -- so an object past this is one no
// cluster would have held, whatever the policy did to it.
const maxMutatedObjectBytes = 1024 * 1024

// maxAccumulatedCopyBytes is how much one patch may grow a document by copying
// parts of it. It is JSONPatchMaxCopyBytes, the apiserver's own default.
const maxAccumulatedCopyBytes = 3 * 1024 * 1024

func init() {
	// A patch may copy a subtree into itself, which doubles the document, and
	// nothing in the CEL budget prices it: twelve of those ops turn a 300-byte
	// object into megabytes for a cost of 490 out of ten million.
	//
	// The apiserver arms this the same way, from JSONPatchMaxCopyBytes, while
	// it builds its GenericAPIServer -- machinery the playground never runs, so
	// the limit would otherwise stay at the package default of unlimited. The
	// error a patch fails with is upstream's own.
	jsonpatch.AccumulatedCopySizeLimit = maxAccumulatedCopyBytes
}

// EvalMutatingAdmissionPolicy evaluates a MutatingAdmissionPolicy against the
// playground's inputs, applying its mutations with the apiserver's own patchers
// (k8s.io/apiserver/pkg/admission/plugin/policy/mutating/patch).
//
// The CEL variables follow apiserver's environment, and each batch is bound the
// way the mutating plugin binds it:
//
//	matchConditions  no namespaceObject, no variables; authorizer bound
//	mutations        namespaceObject bound untrimmed; authorizer bound;
//	                 variables bound, and evaluated afresh for each mutation
//
// `variables` is not declared for matchConditions because the apiserver's
// registry compiles them with a plain, non-composited compiler and refuses a
// policy whose matchConditions name it -- the same gate a
// ValidatingAdmissionPolicy hits.
//
// Evaluation order mirrors the dispatcher: if any matchCondition is false the
// policy does not apply and nothing runs; if one errors, nothing runs either,
// because failurePolicy Fail rejects the request and Ignore skips the policy.
// Otherwise spec.mutations run in order, each against the object the one before
// it produced. A mutation that fails is reported and the ones after it still
// run against the last good object, which is what the dispatcher does with an
// ordinary evaluation error.
func EvalMutatingAdmissionPolicy(policyInput, oldObjectInput, objectValueInput, namespaceInput, requestInput, authorizerInput []byte) (string, error) {
	celInfo, err := extractCelInformation(policyInput, mutatingPolicyKind)
	if err != nil {
		return "", err
	}

	inputs, err := newEvalInputs(oldObjectInput, objectValueInput, namespaceInput, requestInput, authorizerInput)
	if err != nil {
		return "", err
	}

	compiler, err := newPolicyCompiler(celInfo)
	if err != nil {
		return "", err
	}

	sections := evalSections{}
	matched := true
	if len(celInfo.matchConditions) > 0 {
		scope := newMatchConditionScope(inputs)
		for _, matchCondition := range celInfo.matchConditions {
			response := scope.evalExpression(matchCondition.name, &matchConditionExpression{expression: matchCondition.expression}, declsFor(celInfo.hasParams))
			if response.isError() || response.val == nil || response.val.Value() != true {
				matched = false
			}
			sections.matchConditions = append(sections.matchConditions, response)
		}
	}

	if matched {
		sections.evaluateMutations(compiler, inputs, celInfo)
	}
	sections.notSimulated = notSimulated(celInfo)
	sections.decision = sections.mutationDecision(celInfo)

	out, err := json.Marshal(sections.response())
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// evaluateMutations applies spec.mutations in order, threading the object each
// one produces into the next.
func (s *evalSections) evaluateMutations(compiler *policyCompiler, inputs *evalInputs, celInfo *CelInformation) {
	if len(celInfo.mutations) == 0 {
		return
	}
	object := inputs.objectValue
	if object == nil {
		s.failEveryMutation(celInfo, errNoObject)
		return
	}
	gvk := object.GroupVersionKind()
	if gvk.Kind == "" || gvk.Version == "" {
		s.failEveryMutation(celInfo, errNoObjectGVK)
		return
	}

	typeConverter, schemaBacked := typeConverterFor(gvk)
	if !schemaBacked && hasApplyConfiguration(celInfo) {
		s.warnings = append(s.warnings, fmt.Sprintf(
			"There is no merge schema for %s here, so an ApplyConfiguration is merged as if every "+
				"list were atomic: a mutation that adds one list entry replaces the whole list "+
				"instead of merging it by key. The playground carries the schemas of the built-in "+
				"Kubernetes APIs only; a cluster would use the one it serves for %s.",
			gvk.GroupVersion(), gvk.Kind))
	}
	// Whether the pasted object itself fits the schema decides how a patched
	// one is read below: a mutation must not be blamed for a field it inherited.
	objectFitsSchema := schemaBacked
	if schemaBacked {
		if _, err := typeConverter.ObjectToTyped(object); err != nil {
			objectFitsSchema = false
			s.warnings = append(s.warnings, fmt.Sprintf(
				"The object does not fit the %s schema: %v. A cluster would reject it before any "+
					"policy ran, and an ApplyConfiguration cannot merge into it here.", gvk.Kind, err))
		}
	}

	versionedAttributes := &admission.VersionedAttributes{
		Attributes:         inputs.attributes,
		VersionedKind:      inputs.attributes.GetKind(),
		VersionedObject:    object,
		VersionedOldObject: runtimeObject(inputs.oldObjectValue),
	}
	// Everything the playground mutates is unstructured, and
	// runtime.Scheme.ObjectKinds answers for an Unstructured out of the object
	// itself. So the patchers need no registered types, and registering the
	// built-in ones would cost megabytes to answer a question already answered.
	objectInterfaces := admission.NewObjectInterfacesFromScheme(runtime.NewScheme())
	bindings := celplugin.OptionalVariableBindings{Authorizer: inputs.rbacAuthorizer}
	patchDeclarations := declsFor(celInfo.hasParams)
	patchDeclarations.HasPatchTypes = true

	original, err := marshalObjectYAML(object)
	if err != nil {
		s.failEveryMutation(celInfo, err)
		return
	}
	current, mutated := original, false

	for _, mutation := range celInfo.mutations {
		result := &EvalMutationResult{PatchType: string(mutation.patchType)}
		s.mutations = append(s.mutations, result)
		s.mutationScopes = append(s.mutationScopes, nil)

		accessor, newPatcher, err := mutationPatcher(mutation)
		if err != nil {
			setMutationError(result, err)
			continue
		}
		evaluator := compiler.compiler.CompileMutatingEvaluator(accessor, patchDeclarations, environment.NewExpressions)
		if compileErrors := evaluator.CompilationErrors(); len(compileErrors) > 0 {
			setMutationError(result, errors.Join(compileErrors...))
			continue
		}

		// Each mutation gets a whole budget: the dispatcher hands
		// celconfig.RuntimeCELCostBudget to every Patch call, so the budget is
		// per mutation and not per policy.
		budget := int64(celconfig.RuntimeCELCostBudget)
		scope := compiler.newMutationScope()
		s.mutationScopes[len(s.mutationScopes)-1] = scope.scope
		evaluation, remaining, err := evaluator.ForInput(scope, versionedAttributes, inputs.admissionRequest, bindings, inputs.namespace, budget)
		if err != nil {
			setMutationError(result, err)
			continue
		}
		if evaluation.Error != nil {
			setMutationError(result, evaluation.Error)
			continue
		}
		// What the expression itself cost. The budget also paid for the
		// variables it dereferenced, and those are reported one by one.
		expressionCost := uint64(budget-remaining) - calculateVariablesCost(scope.scope)
		result.Cost = &expressionCost

		// Patch evaluates the expression a second time, because upstream's
		// patchers take the expression rather than its value. CEL is
		// side-effect free so the two agree; the throwaway composition context
		// keeps the second pass from being charged or reported twice.
		patched, err := newPatcher(evaluator).Patch(compiler.compiler.CreateContext(context.Background()), patch.Request{
			MatchedResource:     inputs.attributes.GetResource(),
			VersionedAttributes: versionedAttributes,
			ObjectInterfaces:    objectInterfaces,
			OptionalVariables:   bindings,
			Namespace:           inputs.namespace,
			TypeConverter:       typeConverter,
		}, budget)
		if err != nil {
			setMutationError(result, err)
			continue
		}

		// A cluster reads the patched object back through the schema of the type
		// it belongs to: an ApplyConfiguration is parsed against it, and a
		// JSONPatch result is decoded into the typed object strictly. Either way
		// a misspelled field or a quoted number is refused there. The playground
		// keeps everything unstructured, so upstream's patcher takes its
		// unstructured branch and never makes that check; without this the
		// object comes back with `replicas: "10"` and nothing says a cluster
		// would have refused it.
		if objectFitsSchema {
			if _, err := typeConverter.ObjectToTyped(patched); err != nil {
				setMutationError(result, fmt.Errorf(
					"a cluster reads the patched object back against the %s schema and would refuse it: %w", gvk.Kind, err))
				continue
			}
		}

		mutatedYAML, err := marshalObjectYAML(patched)
		if err != nil {
			setMutationError(result, err)
			continue
		}
		if len(mutatedYAML) > maxMutatedObjectBytes {
			// The copy limit armed above bounds a single patch; nothing bounds
			// what a policy accumulates over several. An object this size is
			// past what a cluster would carry in a request body, so it is
			// reported as this mutation failing and is not threaded into the
			// next one.
			setMutationError(result, fmt.Errorf(
				"the mutated object is %d bytes, past the %d a cluster accepts in a request body, "+
					"so it was not applied or passed to the mutations after it",
				len(mutatedYAML), maxMutatedObjectBytes))
			continue
		}

		result.MutatedObject = mutatedYAML
		current, mutated = mutatedYAML, true
		versionedAttributes.VersionedObject = patched
	}

	if !mutated {
		// Nothing applied, so there is no final object: showing the input here
		// would present a re-serialization of what the user typed as a result.
		return
	}
	s.finalObject = current
	s.diff = unifiedDiff(original, current, "object", "mutated")
}

// failEveryMutation reports one reason against every mutation, for the failures
// that belong to the inputs rather than to any one expression.
func (s *evalSections) failEveryMutation(celInfo *CelInformation, err error) {
	for _, mutation := range celInfo.mutations {
		result := &EvalMutationResult{PatchType: string(mutation.patchType)}
		setMutationError(result, err)
		s.mutations = append(s.mutations, result)
	}
}

func setMutationError(result *EvalMutationResult, err error) {
	message := err.Error()
	result.Error = &message
	result.IsError = true
}

// mutationPatcher returns the expression accessor to compile and the upstream
// patcher that applies what it evaluates to. The two go together: the accessor
// decides the CEL return type the expression is checked against, and the
// patcher knows what to do with a value of that type.
func mutationPatcher(mutation CelMutationInfo) (celplugin.ExpressionAccessor, func(celplugin.MutatingEvaluator) patch.Patcher, error) {
	switch mutation.patchType {
	case admissionregistrationv1.PatchTypeApplyConfiguration:
		if mutation.expression == "" {
			return nil, nil, errors.New("patchType is ApplyConfiguration, so applyConfiguration.expression must be set")
		}
		return &patch.ApplyConfigurationCondition{Expression: mutation.expression}, patch.NewApplyConfigurationPatcher, nil
	case admissionregistrationv1.PatchTypeJSONPatch:
		if mutation.expression == "" {
			return nil, nil, errors.New("patchType is JSONPatch, so jsonPatch.expression must be set")
		}
		return &patch.JSONPatchCondition{Expression: mutation.expression}, patch.NewJSONPatcher, nil
	case "":
		return nil, nil, errors.New("patchType is not set; expected ApplyConfiguration or JSONPatch")
	default:
		return nil, nil, fmt.Errorf("unsupported patchType %q; expected ApplyConfiguration or JSONPatch", mutation.patchType)
	}
}

func hasApplyConfiguration(celInfo *CelInformation) bool {
	for _, mutation := range celInfo.mutations {
		if mutation.patchType == admissionregistrationv1.PatchTypeApplyConfiguration {
			return true
		}
	}
	return false
}

// marshalObjectYAML serializes an object for display. Everything reaching here
// is an *unstructured.Unstructured, which marshals itself, so sigs.k8s.io/yaml's
// route through encoding/json needs no intermediate conversion.
func marshalObjectYAML(object runtime.Object) (string, error) {
	out, err := sigsyaml.Marshal(object)
	if err != nil {
		return "", fmt.Errorf("failed to serialize the mutated object: %w", err)
	}
	return string(out), nil
}

// notSimulated lists what this policy asks for that the playground parses and
// then ignores, in the reader's terms. Without it a policy that would never
// fire on a cluster, or would fire against a different object, reports a
// confident result.
func notSimulated(celInfo *CelInformation) string {
	var lines []string
	if celInfo.hasMatchConstraints {
		lines = append(lines, "matchConstraints: the mutations run against whatever is in the Object "+
			"tab, whether or not the resourceRules would select it. Only matchConditions stop a "+
			"mutation from running here.")
	}
	if celInfo.hasParams {
		lines = append(lines, "paramKind: there is no params tab, so params is bound to null -- the "+
			"state a cluster reaches when a binding's paramRef selects nothing.")
	}
	if celInfo.reinvocationPolicy == admissionregistrationv1.IfNeededReinvocationPolicy {
		lines = append(lines, "reinvocationPolicy: IfNeeded asks for another pass once other plugins "+
			"have mutated the object. Each mutation here runs exactly once.")
	}
	if len(celInfo.mutations) > 0 {
		lines = append(lines, "API defaults: the object is used exactly as typed. A cluster defaults it "+
			"before admission and again after every mutation, so a field like imagePullPolicy is "+
			"already set there and a !has(...) guard can fire here where it would not.")
	}
	return strings.Join(lines, "\n")
}
