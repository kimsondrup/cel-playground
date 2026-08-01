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
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"
	celplugin "k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/admission/plugin/policy/mutating/patch"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/cel/environment"
	"sigs.k8s.io/structured-merge-diff/v6/typed"
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

// maxReportedObjectBytes bounds each of the three things the result carries
// besides the expressions: the per-mutation trace, the object at the end, and
// the diff between them. Only the object itself is bounded by
// maxMutatedObjectBytes; nothing bounds how many mutations a policy declares,
// so a hundred of them each echoing an object grown to just under the ceiling
// is megabytes of response for a kilobyte of policy and a few hundred units of
// CEL cost. With this the response is a constant multiple of one object rather
// than a multiple of the policy's length.
const maxReportedObjectBytes = maxMutatedObjectBytes

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
		// The dispatcher skips a patcher when there is no object to patch and
		// admits the request, so this is not a failure -- but it is almost
		// always a blank Object tab rather than a DELETE, so each mutation says
		// what to do about it.
		s.skipEveryMutation(celInfo, errNoObject.Error())
		return
	}
	gvk := object.GroupVersionKind()
	if gvk.Kind == "" || gvk.Version == "" {
		s.failEveryMutation(celInfo, errNoObjectGVK)
		return
	}

	typeConverter, schemaBacked := typeConverterFor(gvk)
	// Whether the pasted object itself fits the schema decides how a patched
	// one is read below: a mutation must not be blamed for a field it inherited.
	objectFitsSchema := schemaBacked
	if schemaBacked {
		// AllowDuplicates because that is what ApplyStructuredMergeDiff parses
		// the live object with; being stricter here would report a schema
		// mismatch the merge itself is happy with.
		if _, err := typeConverter.ObjectToTyped(object, typed.AllowDuplicates); err != nil {
			objectFitsSchema = false
			s.warnings = append(s.warnings, fmt.Sprintf(
				"The object does not fit the %s schema: %v. A cluster would reject it before any "+
					"policy ran, and an ApplyConfiguration cannot merge into it here.", gvk.Kind, err))
		}
	}

	versionedAttributes := &admission.VersionedAttributes{
		Attributes:         inputs.attributes,
		VersionedKind:      inputs.matchedKind,
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
	// Every mutation's output is carried back to the browser, and the per-object
	// ceiling below bounds one of them, not their sum. A policy may declare as
	// many mutations as it likes, and each one echoes the object again.
	reported := len(original)

	for _, mutation := range celInfo.mutations {
		result := &EvalMutationResult{PatchType: string(mutation.patchType)}
		s.mutations = append(s.mutations, result)
		s.mutationScopes = append(s.mutationScopes, nil)
		s.mutationFatal = append(s.mutationFatal, false)

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
		// A merge needs the schema of the type it is merging into, and for a
		// custom resource a cluster reads that from the CRD. Without it there is
		// no honest answer: a CRD that declares listType=map merges by key, and
		// one that declares nothing has an atomic list, which upstream's
		// validatePatch refuses outright. Guessing either way would report a
		// result a cluster contradicts.
		if !schemaBacked && mutation.patchType == admissionregistrationv1.PatchTypeApplyConfiguration {
			setMutationError(result, fmt.Errorf(
				"there is no merge schema for %s here, so what an ApplyConfiguration does to it cannot be "+
					"answered: a cluster reads the schema from the CustomResourceDefinition, and merges by "+
					"key or refuses the patch as atomic depending on what it says. The playground carries "+
					"the schemas of the built-in Kubernetes APIs only; a JSONPatch needs none and still works",
				gvk.GroupVersion()))
			continue
		}

		// Each mutation gets a whole budget: the dispatcher hands
		// celconfig.RuntimeCELCostBudget to every Patch call, so the budget is
		// per mutation and not per policy.
		//
		// A patcher takes a MutatingEvaluator and calls ForInput itself, keeping
		// neither the cost nor the value. Both are read off a decorator in that
		// slot, so the expression is evaluated exactly once -- by upstream, on
		// the way to being applied -- and the panel still gets a cost.
		budget := int64(celconfig.RuntimeCELCostBudget)
		scope := compiler.newMutationScope()
		s.mutationScopes[len(s.mutationScopes)-1] = scope.scope
		metered := &meteredEvaluator{MutatingEvaluator: evaluator}
		patched, err := newPatcher(metered).Patch(scope, patch.Request{
			MatchedResource:     inputs.matchedResource,
			VersionedAttributes: versionedAttributes,
			ObjectInterfaces:    objectInterfaces,
			OptionalVariables:   bindings,
			Namespace:           inputs.namespace,
			TypeConverter:       typeConverter,
		}, budget)
		if metered.charged {
			// What the expression itself cost. The budget also paid for the
			// variables it dereferenced, and those are reported one by one.
			expressionCost := uint64(budget-metered.remaining) - calculateVariablesCost(scope.scope)
			result.Cost = &expressionCost
		}
		if err != nil {
			// A mutation that overruns its budget reports no remaining budget,
			// so result.Cost stays empty -- but celconfig.PerCallLimit caps any
			// one expression at a tenth of the budget, so the only way to
			// overrun is across variables, and those are in the scope and
			// counted. The budget section sees the overrun through them.
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
		//
		// It is not a failure failurePolicy can excuse: a patched object the
		// apiserver cannot decode comes back as a StatusError, and the
		// dispatcher returns those rather than collecting them, so they never
		// reach the failurePolicy filter.
		if objectFitsSchema {
			if _, err := typeConverter.ObjectToTyped(patched, typed.AllowDuplicates); err != nil {
				s.mutationFatal[len(s.mutationFatal)-1] = true
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

		current, mutated = mutatedYAML, true
		versionedAttributes.VersionedObject = patched
		// The object is applied whatever happens; what is bounded is how much of
		// it travels back. Past the ceiling the trace is dropped and the final
		// object below carries the answer on its own.
		if reported+len(mutatedYAML) > maxReportedObjectBytes {
			result.Message = fmt.Sprintf(
				"applied, and not shown: the objects this policy has produced come to more than the %d bytes "+
					"the playground will send back. The final object below is what the last mutation left.",
				maxReportedObjectBytes)
			continue
		}
		reported += len(mutatedYAML)
		result.MutatedObject = mutatedYAML
	}

	if !mutated {
		// Nothing applied, so there is no final object: showing the input here
		// would present a re-serialization of what the user typed as a result.
		return
	}
	s.finalObject = current
	// The diff of two objects near the ceiling is larger than either of them,
	// and it is the least useful of the three when it is that big.
	if diff := unifiedDiff(original, current, "object", "mutated"); len(diff) <= maxReportedObjectBytes {
		s.diff = diff
	} else {
		s.warnings = append(s.warnings, fmt.Sprintf(
			"The object changed by more than the %d bytes of diff the playground will send back, so no "+
				"diff is shown. The object at the end is below.", maxReportedObjectBytes))
	}
}

// meteredEvaluator records what one mutation's expression cost.
//
// patch.Patcher takes a plugincel.MutatingEvaluator and calls ForInput itself,
// then throws the remaining budget away and returns only the patched object.
// Sitting in that slot is the only place the cost is visible without evaluating
// the expression a second time.
type meteredEvaluator struct {
	celplugin.MutatingEvaluator
	remaining int64
	// charged distinguishes a mutation that ran and cost nothing from one whose
	// patcher never got as far as evaluating it.
	charged bool
}

func (e *meteredEvaluator) ForInput(ctx context.Context, versionedAttr *admission.VersionedAttributes, request *admissionv1.AdmissionRequest, inputs celplugin.OptionalVariableBindings, namespace *corev1.Namespace, budget int64) (celplugin.EvaluationResult, int64, error) {
	evaluation, remaining, err := e.MutatingEvaluator.ForInput(ctx, versionedAttr, request, inputs, namespace, budget)
	if err == nil {
		e.remaining, e.charged = remaining, true
	}
	return evaluation, remaining, err
}

// failEveryMutation reports one reason against every mutation, for the failures
// that belong to the inputs rather than to any one expression.
func (s *evalSections) failEveryMutation(celInfo *CelInformation, err error) {
	for _, mutation := range celInfo.mutations {
		result := &EvalMutationResult{PatchType: string(mutation.patchType)}
		setMutationError(result, err)
		s.mutations = append(s.mutations, result)
		s.mutationFatal = append(s.mutationFatal, false)
	}
}

// skipEveryMutation reports that no mutation ran, without calling it a failure.
func (s *evalSections) skipEveryMutation(celInfo *CelInformation, message string) {
	s.mutationsSkipped = true
	for _, mutation := range celInfo.mutations {
		s.mutations = append(s.mutations, &EvalMutationResult{
			PatchType: string(mutation.patchType),
			Message:   message,
		})
		s.mutationFatal = append(s.mutationFatal, false)
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
		lines = append(lines, matchConstraintsCaveat(len(celInfo.mutations) > 0))
	}
	if celInfo.hasParams {
		lines = append(lines, "paramKind: there is no params tab, so params is bound to null -- the "+
			"state a cluster reaches when a binding names no paramRef at all. A binding whose paramRef "+
			"selects nothing behaves differently again: it either skips the policy or denies the "+
			"request, depending on parameterNotFoundAction.")
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

// matchConstraintsCaveat is shared with the validating mode: neither evaluates
// spec.matchConstraints, because matching needs the request's resource -- the
// plural -- and nothing in a browser can derive `deployments` from
// `kind: Deployment` without discovery.
func matchConstraintsCaveat(mutating bool) string {
	acts, gate := "validations run", "validation"
	if mutating {
		acts, gate = "mutations run", "mutation"
	}
	return "matchConstraints: the " + acts + " against whatever is in the Object tab, whether or not " +
		"the resourceRules would select it. Only matchConditions stop a " + gate + " from running here."
}

// validatingNotSimulated is the validating mode's half of the same list.
func validatingNotSimulated(celInfo *CelInformation) string {
	var lines []string
	if celInfo.hasMatchConstraints {
		lines = append(lines, matchConstraintsCaveat(false))
	}
	if celInfo.hasParams {
		lines = append(lines, "paramKind: there is no params tab, so params is bound to null -- the "+
			"state a cluster reaches when a binding names no paramRef at all. A binding whose paramRef "+
			"selects nothing behaves differently again: it either skips the policy or denies the "+
			"request, depending on parameterNotFoundAction.")
	}
	return strings.Join(lines, "\n")
}
