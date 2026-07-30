// Copyright 2023 Undistro Authors
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
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/interpreter"
	"gopkg.in/yaml.v3"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	admissionregistrationv1alpha1 "k8s.io/api/admissionregistration/v1alpha1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	plugincel "k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/admission/plugin/policy/mutating/patch"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/cel/environment"
	"k8s.io/client-go/kubernetes/scheme"
	sigsyaml "sigs.k8s.io/yaml"
)

// Sentinel errors for inputs that make mutation evaluation impossible. They are
// reported against each mutation rather than failing the whole evaluation, so
// the matchCondition and variable results are not thrown away.
var (
	errNoObject    = errors.New("an object is required to evaluate mutations")
	errNoObjectGVK = errors.New("the object must set apiVersion and kind to be mutated")
)

// EvalMutatingAdmissionPolicy evaluates a Kubernetes MutatingAdmissionPolicy
// against the supplied inputs and returns the result as a JSON document.
//
// MutatingAdmissionPolicy is GA as admissionregistration.k8s.io/v1 in
// Kubernetes 1.36; v1beta1 (1.34) and v1alpha1 (1.32) documents are accepted
// too and evaluated identically, since the three schemas are structurally the
// same.
//
// Evaluation order mirrors the apiserver:
//
//  1. matchConditions. If any evaluates to false the policy does not apply and
//     no mutation runs.
//  2. spec.variables, lazily, so an unreferenced variable costs nothing.
//  3. spec.mutations, in order, each one applied to the output of the previous
//     one. Both ApplyConfiguration (server-side-apply merge) and JSONPatch
//     patch types are supported. A failing mutation is reported and the
//     remaining ones still run against the last good object, so one broken
//     expression does not hide the rest. The apiserver's dispatcher does the
//     same for an ordinary evaluation error -- it records the error and
//     continues -- and differs only for a StatusError, which aborts the policy
//     outright.
//
// The CEL variables available to mutation expressions are `object`,
// `oldObject`, `request`, `namespaceObject`, `variables` and `authorizer`.
//
// Not supported, matching the ValidatingAdmissionPolicy mode: `params` /
// paramKind bindings, matchConstraints resource matching (the playground has no
// GVR context to match against), and reinvocationPolicy re-invocation loops --
// each mutation is evaluated exactly once. failurePolicy and reinvocationPolicy
// are parsed and reported but do not change playground behavior, since there is
// no request here to fail.
func EvalMutatingAdmissionPolicy(policyInput, oldObjectInput, objectValueInput, namespaceInput, requestInput, authorizerInput []byte) (string, error) {
	policy, err := deserializeMutatingAdmissionPolicy(policyInput)
	if err != nil {
		return "", err
	}
	celInfo := extractMAPV1CelInformation(policy)

	oldObjectValue, err := decodeObjectInput(oldObjectInput)
	if err != nil {
		return "", fmt.Errorf("failed to decode input for the old resource value: %w", err)
	}

	objectValue, err := decodeObjectInput(objectValueInput)
	if err != nil {
		return "", fmt.Errorf("failed to decode input for the new resource value: %w", err)
	}

	namespaceObject, err := deserializeNamespace(namespaceInput)
	if err != nil {
		return "", err
	}

	request, err := deserializeRequest(requestInput)
	if err != nil {
		return "", err
	}

	var authorizer Authorizer
	if err := yaml.Unmarshal(authorizerInput, &authorizer); err != nil {
		return "", fmt.Errorf("failed to decode input for the authorizer: %w", err)
	}
	initReceiver(&authorizer.receiverOnlyObjectVal, AuthorizerType)

	authorizerRequestResource, err := getAuthorizerRequestResource(&authorizer, request)
	if err != nil {
		return "", err
	}

	// The playground evaluates matchConditions and spec.variables with its own
	// CEL environment so that intermediate values can be reported, exactly as
	// the ValidatingAdmissionPolicy mode does. The mutations themselves are
	// handed to the apiserver's own compiler further down, which is the only
	// way to get faithful Object{}/JSONPatch{} semantics.
	celVars := []cel.EnvOption{}
	inputData := map[string]any{}

	if objectValue != nil {
		cleanMetaData(objectValue)
		celVars = updateVars("object", celVars, inputData, objectValue)
	}
	if oldObjectValue != nil {
		cleanMetaData(oldObjectValue)
		celVars = updateVars("oldObject", celVars, inputData, oldObjectValue)
	}
	if request != nil {
		celVars = updateVars("request", celVars, inputData, request)
	}
	if namespaceObject != nil {
		celVars = updateVars("namespaceObject", celVars, inputData, namespaceObject)
	}
	if authorizerRequestResource != nil {
		celVars = updateVars("authorizer.requestResource", celVars, inputData, authorizerRequestResource)
	}
	celVars = updateVars("authorizer", celVars, inputData, &authorizer)

	envOptions := append([]cel.EnvOption{}, celEnvOptions...)
	envOptions = append(envOptions, celVars...)
	env, err := cel.NewEnv(envOptions...)
	if err != nil {
		return "", fmt.Errorf("failed to create CEL env: %w", err)
	}

	activations, err := interpreter.NewActivation(inputData)
	if err != nil {
		return "", fmt.Errorf("failed to create CEL activations: %w", err)
	}

	variableLazyEvals := lazyEvalMap{}
	variableNames := []string{}
	if len(celInfo.variables) > 0 {
		env, variableNames, err = initVars(env, celInfo.variables, variableLazyEvals, activations, inputData)
		if err != nil {
			return "", fmt.Errorf("failed to initialize variables: %w", err)
		}
	}

	// The apiserver never mutates when a matchCondition errors: failurePolicy
	// Fail rejects the request and Ignore skips the policy, and neither runs
	// the mutations. An errored condition therefore counts as "not matched"
	// here, so the playground cannot show a mutated object that a cluster would
	// never produce.
	matchConditions := true
	matchConditionsEvals := []*evalResponse{}
	for _, matchCondition := range celInfo.matchConditions {
		ast, issues := env.Parse(matchCondition.expression)
		if issues.Err() != nil {
			return "", fmt.Errorf("failed to parse expression %s: %w", matchCondition.expression, issues.Err())
		}
		var val *evalResponse
		if prog, err := env.Program(ast, celProgramOptions...); err != nil {
			matchConditions = false
			val = newEvalResponseErr("parsing", matchCondition.expression, err)
		} else if exprEval, details, err := prog.Eval(activations); err != nil {
			matchConditions = false
			val = newEvalResponseErr("evaluating", matchCondition.expression, err)
		} else {
			matchConditions = matchConditions && (exprEval.Value() == true)
			val = newEvalResponse(matchCondition.name, exprEval, details, "", nil)
		}
		matchConditionsEvals = append(matchConditionsEvals, val)
	}

	// Whatever the matchConditions read was evaluated by this environment and
	// nothing else accounts for it. Taken before the mutations force anything
	// else, because those are charged separately below.
	matchConditionVariableCost := calculateLazyEvalCost(variableLazyEvals)

	var mutations []*EvalMutationResult
	var finalObject, diff string
	var mutationCost uint64
	var warnings []string

	// What the policy asks for that this mode does not simulate. It is a property
	// of the policy document, so it is reported whatever the matchConditions do and
	// whether or not any mutation runs -- a policy gated off by its own
	// matchConditions is exactly when the reader needs to know that params are
	// unbound here.
	schemaBacked := false
	if objectValue != nil {
		if gvk := (&unstructured.Unstructured{Object: objectValue}).GroupVersionKind(); gvk.Kind != "" {
			_, schemaBacked = typeConverterFor(gvk)
		}
	}
	caveats := notSimulated(policy, schemaBacked)

	// Reported whatever the matchConditions do, since a dropped field may be the
	// reason they did what they did.
	if unknown := unknownPolicyFields(policyInput); len(unknown) > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"The policy document has fields this playground does not know and dropped: %s. It was "+
				"evaluated without them -- a misspelled matchConditions removes the gate rather "+
				"than failing -- while a cluster would reject the document.",
			strings.Join(unknown, ", ")))
	}

	if matchConditions && len(celInfo.mutations) > 0 {
		// The mutations run in the apiserver's environment, not this one, so a
		// variable only they read would never be evaluated here and the panel
		// would have nothing to show for it. Evaluate exactly those.
		//
		// Only those: a cluster binds variables lazily and never evaluates one
		// nothing reads, so forcing every declared variable would report an
		// error against a variable that a cluster would not have run.
		for _, name := range mutationVariables(policy, celInfo.variables) {
			if lazyEval, ok := variableLazyEvals[name]; ok && lazyEval.val == nil {
				lazyEval.eval(env, activations)
			}
		}

		run, err := evalMutations(policy, objectValueInput, oldObjectInput, requestInput, namespaceInput, &authorizer)
		switch {
		case errors.Is(err, errNoObject), errors.Is(err, errNoObjectGVK):
			// Report this against each mutation rather than failing the whole
			// evaluation, so the matchCondition and variable results the user
			// did get are still rendered.
			mutations = make([]*EvalMutationResult, 0, len(celInfo.mutations))
			for _, mutation := range celInfo.mutations {
				result := &EvalMutationResult{PatchType: mutation.patchType}
				setMutationError(result, err)
				mutations = append(mutations, result)
			}
		case err != nil:
			return "", err
		default:
			mutations, finalObject, diff = run.results, run.finalObject, run.diff
			mutationCost = run.cost
			warnings = append(warnings, run.warnings...)
		}
	}

	// A mutation that evaluated has already been charged for the composited
	// re-evaluation of the variables it reads, so the display-side evaluation of
	// those is not added on top of it; it exists only to surface the values.
	// What a matchCondition read is not in that figure, so it is added
	// separately. Where no mutation got that far -- a compile error, a missing
	// object -- the display-side evaluation is the only thing that ran, and
	// charging nothing for it would report a cost of zero for work the panel
	// shows.
	cost := calculateEvalResponsesCost(matchConditionsEvals)
	if mutationCost > 0 {
		cost += mutationCost + matchConditionVariableCost
	} else {
		cost += calculateLazyEvalCost(variableLazyEvals)
	}

	response := &EvalResponse{
		Warnings:           warnings,
		MatchConditions:    generateEvalResults(matchConditionsEvals),
		MutationVariables:  generateEvalVariables(variableNames, variableLazyEvals),
		Mutations:          mutations,
		Diff:               diff,
		FinalObject:        finalObject,
		NotSimulated:       caveats,
		FailurePolicy:      celInfo.failurePolicy,
		ReinvocationPolicy: celInfo.reinvocationPolicy,
		Cost:               &cost,
	}

	out, err := json.Marshal(response)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// deserializeMutatingAdmissionPolicy decodes a MutatingAdmissionPolicy from any
// of the served API versions and normalizes it onto the v1 shape.
func deserializeMutatingAdmissionPolicy(input []byte) (*admissionregistrationv1.MutatingAdmissionPolicy, error) {
	deser, err := deserializeCelInformation(input)
	if err != nil {
		return nil, fmt.Errorf("failed to decode input: %w", err)
	}
	switch resource := deser.(type) {
	case *admissionregistrationv1.MutatingAdmissionPolicy:
		return resource, nil
	case *admissionregistrationv1beta1.MutatingAdmissionPolicy:
		return convertMAP(resource)
	case *admissionregistrationv1alpha1.MutatingAdmissionPolicy:
		return convertMAP(resource)
	default:
		return nil, fmt.Errorf("expected a MutatingAdmissionPolicy, got %T", deser)
	}
}

// notSimulated lists what this policy asks for that the playground parses and
// then ignores, in the reader's terms rather than the implementation's. Every
// entry is also in the mode's documented deviations, which is no use to somebody
// looking at the panel: without this, a policy that would never fire on a
// cluster, or would fire with different values, reports a confident result.
func notSimulated(policy *admissionregistrationv1.MutatingAdmissionPolicy, schemaBacked bool) string {
	var lines []string
	if policy.Spec.MatchConstraints != nil {
		lines = append(lines, "matchConstraints: the mutations ran against whatever is in the "+
			"Object tab, whether or not the resourceRules would select it. Only matchConditions "+
			"can stop a mutation from running here.")
	}
	if policy.Spec.ParamKind != nil {
		lines = append(lines, "paramKind: there is no params input, so params is bound to nothing. "+
			"An expression reading it errors, and has(params...) is false where a cluster would "+
			"find the object.")
	}
	if policy.Spec.ReinvocationPolicy == admissionregistrationv1.IfNeededReinvocationPolicy {
		lines = append(lines, "reinvocationPolicy: IfNeeded asks for another pass after other "+
			"plugins mutate. Each mutation here runs exactly once.")
	}
	if !ignoresFailures(policy) {
		// Unset counts: the default is Fail, which is exactly the setting whose
		// effect is missing here.
		lines = append(lines, "failurePolicy: Fail asks the apiserver to deny the request when a "+
			"mutation fails. There is no request to deny here, so a failed mutation is reported "+
			"and the rest still run.")
	}
	if schemaBacked {
		lines = append(lines, "API defaults: the object is used exactly as typed. A cluster "+
			"defaults it before admission runs and again after every mutation, so fields like "+
			"imagePullPolicy are already set there -- a !has(...) guard can look like it fires "+
			"here when it would not.")
	}
	return strings.Join(lines, "\n")
}

// unknownPolicyFields reports fields in the pasted document that the vendored
// MutatingAdmissionPolicy type does not know. The decoder above is the lenient
// one the other modes use, so it drops them: a policy whose matchConditions key
// is misspelled loses the gate entirely and every mutation runs unguarded, with
// nothing on screen to say so. A cluster refuses the document instead, since
// kubectl and the apiserver both validate fields strictly.
//
// The three served versions have structurally identical schemas, so checking the
// input against the v1 type is valid whichever apiVersion it declares.
func unknownPolicyFields(input []byte) []string {
	var probe admissionregistrationv1.MutatingAdmissionPolicy
	err := sigsyaml.UnmarshalStrict(input, &probe)
	if err == nil {
		return nil
	}
	var fields []string
	for _, match := range unknownFieldPattern.FindAllStringSubmatch(err.Error(), -1) {
		fields = append(fields, match[1])
	}
	slices.Sort(fields)
	return slices.Compact(fields)
}

// unknownFieldPattern matches the field name in sigs.k8s.io/yaml's strict-mode
// complaint. Anything else in that error is a shape problem the lenient decode
// above has already reported on its own terms.
// variableReference matches a read of a spec.variables entry. Kubernetes binds
// them under a map called variables, so every read is variables.<name> and a
// name is an ordinary CEL identifier.
var variableReference = regexp.MustCompile(`\bvariables\.([a-zA-Z_][a-zA-Z0-9_]*)`)

// mutationVariables returns the spec.variables entries the policy's mutation
// expressions read, whether directly or through another variable, in the order
// they are declared -- which is the order they are allowed to refer to each
// other in.
//
// Reading the expressions is an over-approximation: variables.x inside a string
// literal counts as a read. That errs towards showing a variable the mutations
// might not reach, which costs the reader a row in the panel, rather than
// hiding one they are looking for.
func mutationVariables(policy *admissionregistrationv1.MutatingAdmissionPolicy, variables []CelVariableInfo) []string {
	read := map[string]bool{}
	var scan func(expression string)
	scan = func(expression string) {
		for _, match := range variableReference.FindAllStringSubmatch(expression, -1) {
			name := match[1]
			if read[name] {
				continue
			}
			read[name] = true
			for _, variable := range variables {
				if variable.name == name {
					scan(variable.expression)
				}
			}
		}
	}
	for _, mutation := range policy.Spec.Mutations {
		if mutation.ApplyConfiguration != nil {
			scan(mutation.ApplyConfiguration.Expression)
		}
		if mutation.JSONPatch != nil {
			scan(mutation.JSONPatch.Expression)
		}
	}
	names := []string{}
	for _, variable := range variables {
		if read[variable.name] {
			names = append(names, variable.name)
		}
	}
	return names
}

var unknownFieldPattern = regexp.MustCompile(`unknown field "([^"]+)"`)

// mutationRun is the outcome of evaluating a policy's spec.mutations.
type mutationRun struct {
	results     []*EvalMutationResult
	finalObject string
	diff        string
	cost        uint64
	warnings    []string
}

// evalMutations compiles and applies spec.mutations in order, threading the
// object produced by each mutation into the next one.
func evalMutations(policy *admissionregistrationv1.MutatingAdmissionPolicy, objectInput, oldObjectInput, requestInput, namespaceInput []byte, authorizer *Authorizer) (*mutationRun, error) {
	object, err := decodeUnstructured(objectInput)
	if err != nil {
		return nil, fmt.Errorf("failed to decode input for the new resource value: %w", err)
	}
	if object == nil {
		return nil, errNoObject
	}
	oldObject, err := decodeUnstructured(oldObjectInput)
	if err != nil {
		return nil, fmt.Errorf("failed to decode input for the old resource value: %w", err)
	}

	gvk := object.GroupVersionKind()
	if gvk.Kind == "" || gvk.Version == "" {
		return nil, errNoObjectGVK
	}

	namespace, err := decodeNamespaceObject(namespaceInput)
	if err != nil {
		return nil, err
	}

	request := &AdmissionRequest{}
	if len(requestInput) > 0 {
		if err := yaml.Unmarshal(requestInput, request); err != nil {
			return nil, fmt.Errorf("failed to decode input for the request: %w", err)
		}
	}

	// The Request tab wins wherever it is filled in, so that `request.name`,
	// `request.namespace` and `request.kind` -- and the authorizer checks keyed
	// on them -- report the same values inside a mutation expression as they do
	// in a matchCondition, which reads the tab directly.
	gvr := requestResource(request, gvk)
	name := cmp.Or(request.Name, object.GetName())
	objectNamespace := cmp.Or(request.Namespace, object.GetNamespace())
	requestGVK := requestKind(request.Kind, gvk)
	attributeGVK := requestGVK
	if request.RequestKind != nil {
		attributeGVK = requestKind(*request.RequestKind, requestGVK)
	}

	// runtime.Object is an interface, so passing a nil *unstructured.Unstructured
	// straight in would produce a non-nil interface wrapping a nil pointer:
	// GetOldObject() would then look present and panic on first dereference.
	// Normalize it to a genuine nil interface, which is what "no oldObject"
	// means to every consumer downstream.
	var oldObjectArg runtime.Object
	if oldObject != nil {
		oldObjectArg = oldObject
	}

	operation := admissionOperation(request.Operation)
	attributes := admission.NewAttributesRecord(
		object, oldObjectArg, attributeGVK,
		objectNamespace, name, gvr,
		request.SubResource, operation, operationOptions(operation),
		request.DryRun != nil && *request.DryRun,
		requestUser(request),
	)
	versionedAttributes := &admission.VersionedAttributes{
		Attributes: attributes,
		// The patchers rebuild an AdmissionRequest from this, so it is what
		// request.kind reads inside a mutation expression. It has to be the kind the
		// Request tab names, or one expression answers the tab in a matchCondition
		// and the object's own kind in a mutation.
		VersionedKind:      requestGVK,
		VersionedObject:    object,
		VersionedOldObject: oldObjectArg,
	}

	// Rebuild what the apiserver's unexported compilePolicy does, from the
	// exported building blocks.
	compiler, err := plugincel.NewCompositedCompiler(environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion()))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize CEL compiler: %w", err)
	}
	declarations := plugincel.OptionalVariableDeclarations{
		HasParams:     policy.Spec.ParamKind != nil,
		HasAuthorizer: true,
	}
	compiler.CompileAndStoreVariables(namedVariables(policy.Spec.Variables), declarations, environment.StoredExpressions)
	patchDeclarations := declarations
	patchDeclarations.HasPatchTypes = true

	authorizerAdapter := &mutationAuthorizer{
		config:      authorizer,
		requestUser: request.UserInfo.Username,
	}
	bindings := plugincel.OptionalVariableBindings{Authorizer: authorizerAdapter}
	objectInterfaces := admission.NewObjectInterfacesFromScheme(scheme.Scheme)
	typeConverter, schemaBacked := typeConverterFor(gvk)

	var warnings []string
	// The fields the pasted object already carried, so a mutation is only
	// blamed for the ones it adds.
	var objectUndeclared []string
	if !schemaBacked {
		// Only an ApplyConfiguration merge depends on the schema, so a
		// JSONPatch-only policy is not warned about on its account.
		if hasApplyConfiguration(policy) {
			// The warning is the only signal the user gets: a schemaless merge
			// does not fail, it quietly does the wrong thing. patch/smd.go's
			// validatePatch would reject mutating an atomic list, and the
			// deduced type's list *is* atomic, but findAtomics descends via
			// Map.FindField -- which always misses on the deduced type, since
			// it declares no fields -- so the check never gets past the root
			// and the list is replaced without complaint.
			warnings = append(warnings, fmt.Sprintf(
				"No schema for %s, so ApplyConfiguration merges are approximate: lists are "+
					"treated as atomic, and a mutation that adds a list entry replaces the whole "+
					"list instead of merging it by key. The playground has schemas for the "+
					"built-in Kubernetes APIs only; a cluster would use the one it has registered "+
					"for %s.",
				gvk.GroupVersion().String(), gvk.Kind))
		}
	} else if undeclared, more := undeclaredFields(gvk, object); len(undeclared) > 0 {
		// Reported once for the whole object rather than once per field, so an
		// object with several unknown fields does not bury the rest of the
		// result under warnings.
		objectUndeclared = undeclared
		warnings = append(warnings, fmt.Sprintf(
			"The schema for %s does not declare: %s%s. The mutation was applied with those "+
				"fields preserved, but the playground's schema is only as new as the client-go "+
				"it was built against -- a field from a newer Kubernetes would be accepted by a "+
				"cluster, while a misspelled one would be rejected.",
			gvk.GroupVersion().String()+" "+gvk.Kind, strings.Join(undeclared, ", "), andPossiblyMore(more)))
	}

	ctx := compiler.CreateContext(context.Background())
	admissionRequest := plugincel.CreateAdmissionRequest(
		attributes,
		metav1.GroupVersionResource(gvr),
		metav1.GroupVersionKind(requestGVK),
	)

	originalYAML, err := marshalObjectYAML(object)
	if err != nil {
		return nil, err
	}

	var totalCost uint64
	results := make([]*EvalMutationResult, 0, len(policy.Spec.Mutations))
	currentYAML := originalYAML
	mutated := false

	for _, mutation := range policy.Spec.Mutations {
		result := &EvalMutationResult{PatchType: string(mutation.PatchType)}
		results = append(results, result)
		// Lets the authorizer adapter attribute a selector-narrowed check to the
		// mutation that asked it, whichever of the paths below the mutation
		// leaves by.
		authorizerAdapter.mutation = len(results)

		evaluator, patcher, err := compileMutation(compiler, mutation, patchDeclarations)
		if err != nil {
			setMutationError(result, err)
			continue
		}

		// patch.Patcher.Patch does not report cost, so the expression is first
		// evaluated directly to measure it. CEL is side-effect free, so the
		// second evaluation inside Patch produces the same value.
		if compileErrs := evaluator.CompilationErrors(); len(compileErrs) > 0 {
			setMutationError(result, errors.Join(compileErrs...))
			continue
		}
		// Each mutation gets the full budget, the way the apiserver's dispatcher
		// hands celconfig.RuntimeCELCostBudget to every Patch call; the budget is
		// per expression, not per policy.
		budget := int64(celconfig.RuntimeCELCostBudget)
		evaluation, remaining, err := evaluator.ForInput(ctx, versionedAttributes, admissionRequest, bindings, namespace, budget)
		if err != nil {
			setMutationError(result, err)
			continue
		}
		if evaluation.Error != nil {
			setMutationError(result, evaluation.Error)
			continue
		}
		cost := uint64(budget - remaining)
		result.Cost = &cost
		totalCost += cost

		patched, err := patcher.Patch(ctx, patch.Request{
			MatchedResource:     gvr,
			VersionedAttributes: versionedAttributes,
			ObjectInterfaces:    objectInterfaces,
			OptionalVariables:   bindings,
			Namespace:           namespace,
			TypeConverter:       typeConverter,
		}, budget)
		if err != nil {
			setMutationError(result, err)
			continue
		}

		// What the mutation wrote is checked against the schema, not only what
		// the user pasted. The permissive schema that keeps a field from a newer
		// Kubernetes out of the way applies to the patch too, and a cluster is
		// strict about both: it parses an ApplyConfiguration patch against its
		// own schema, and decodes a JSONPatch result into a typed object. Either
		// way a misspelled field is refused there and merged here, and the
		// expression is the likeliest place for a typo, since Object{} and
		// JSONPatch paths have no compile-time field checking. Fields the input
		// object already carried are left to the object-level warning above.
		undeclared, more := undeclaredFields(gvk, patched)
		if added := without(undeclared, objectUndeclared); len(added) > 0 {
			warnings = append(warnings, fmt.Sprintf(
				"Mutation %d writes fields the schema for %s does not declare: %s%s. The "+
					"playground's schema is only as new as the client-go it was built against, "+
					"so a field from a newer Kubernetes would be applied by a cluster -- but a "+
					"misspelled one would be rejected rather than applied, and a mutation "+
					"expression has no compile-time field checking to catch that.",
				len(results), gvk.GroupVersion().String()+" "+gvk.Kind,
				strings.Join(added, ", "), andPossiblyMore(more)))
		}
		// What this mutation leaves behind is the next one's input, so it becomes
		// the baseline to subtract there. Without this, one typo is blamed on
		// every mutation that runs after it as well as the one that wrote it.
		objectUndeclared = undeclared

		mutatedYAML, err := marshalObjectYAML(patched)
		if err != nil {
			return nil, err
		}
		result.MutatedObject = mutatedYAML
		currentYAML = mutatedYAML
		mutated = true

		// Feed this mutation's output into the next one.
		versionedAttributes.VersionedObject = patched
	}

	// A selector-narrowed authorizer check answers here instead of failing, and
	// answers from the un-narrowed fixture entry, so the decision looks ordinary
	// and can be the opposite of the cluster's. Reported per mutation, since
	// which mutation to distrust is the useful part.
	for _, narrowed := range authorizerAdapter.narrowedMutations {
		warnings = append(warnings, fmt.Sprintf(
			"Mutation %d narrows an authorizer check with fieldSelector() or labelSelector(). "+
				"The Authorizer tab has no way to express a selector, so the check was answered "+
				"from the un-narrowed entry rather than refused -- a cluster that grants the verb "+
				"only for some selectors would answer differently, so do not trust that decision.",
			narrowed))
	}

	// A cluster does not stop at reporting a failed mutation: unless
	// failurePolicy is Ignore, the collected error denies the whole request. The
	// playground has nothing to reject, so it shows the partial result -- which
	// looks like a success unless it says otherwise.
	if failed := firstFailedMutation(results); failed > 0 && !ignoresFailures(policy) {
		warnings = append(warnings, fmt.Sprintf(
			"Mutation %d failed. The rest still ran so their output is visible, but this policy "+
				"does not set failurePolicy: Ignore, so a cluster would have denied the request "+
				"instead of applying anything.", failed))
	}

	run := &mutationRun{
		results:  results,
		cost:     totalCost,
		warnings: warnings,
	}
	if !mutated {
		// Nothing was applied, so there is no "final object" to show. Returning
		// the input here would present a re-serialized copy of what the user
		// typed as though it were a result.
		return run, nil
	}
	// The per-mutation objects above are a debugging trace the API itself does
	// not have; this is the object the last mutation produced. Reported even
	// when a single mutation's output already equals it, since it is the one
	// result that answers what the policy did as a whole. It is not what a
	// cluster would store: nothing here is defaulted, and other policies and
	// webhooks would run after this one.
	run.finalObject = currentYAML
	run.diff = unifiedDiff(originalYAML, currentYAML, "object", "mutated")
	return run, nil
}

// firstFailedMutation returns the 1-based position of the first mutation that
// did not apply, or 0 when they all did.
func firstFailedMutation(results []*EvalMutationResult) int {
	for i, result := range results {
		if result.IsError {
			return i + 1
		}
	}
	return 0
}

// ignoresFailures reports whether the policy asks for a failed mutation to be
// skipped rather than to deny the request. Unset means Fail.
func ignoresFailures(policy *admissionregistrationv1.MutatingAdmissionPolicy) bool {
	return policy.Spec.FailurePolicy != nil &&
		*policy.Spec.FailurePolicy == admissionregistrationv1.Ignore
}

// hasApplyConfiguration reports whether any mutation uses the patch type that
// depends on a schema for its merge semantics.
func hasApplyConfiguration(policy *admissionregistrationv1.MutatingAdmissionPolicy) bool {
	for _, mutation := range policy.Spec.Mutations {
		if mutation.PatchType == admissionregistrationv1.PatchTypeApplyConfiguration &&
			mutation.ApplyConfiguration != nil {
			return true
		}
	}
	return false
}

// compileMutation builds the evaluator and patcher for a single mutation.
func compileMutation(compiler *plugincel.CompositedCompiler, mutation admissionregistrationv1.Mutation, declarations plugincel.OptionalVariableDeclarations) (plugincel.MutatingEvaluator, patch.Patcher, error) {
	switch mutation.PatchType {
	case admissionregistrationv1.PatchTypeApplyConfiguration:
		if mutation.ApplyConfiguration == nil {
			return nil, nil, fmt.Errorf("patchType is ApplyConfiguration but applyConfiguration is not set")
		}
		accessor := &patch.ApplyConfigurationCondition{Expression: mutation.ApplyConfiguration.Expression}
		evaluator := compiler.CompileMutatingEvaluator(accessor, declarations, environment.StoredExpressions)
		return evaluator, patch.NewApplyConfigurationPatcher(evaluator), nil
	case admissionregistrationv1.PatchTypeJSONPatch:
		if mutation.JSONPatch == nil {
			return nil, nil, fmt.Errorf("patchType is JSONPatch but jsonPatch is not set")
		}
		accessor := &patch.JSONPatchCondition{Expression: mutation.JSONPatch.Expression}
		evaluator := compiler.CompileMutatingEvaluator(accessor, declarations, environment.StoredExpressions)
		return evaluator, patch.NewJSONPatcher(evaluator), nil
	default:
		return nil, nil, fmt.Errorf("unsupported patchType %q, expected ApplyConfiguration or JSONPatch", mutation.PatchType)
	}
}

func setMutationError(result *EvalMutationResult, err error) {
	message := err.Error()
	result.Error = &message
	result.IsError = true
}

// mutationVariable is a plugincel.NamedExpressionAccessor for a
// spec.variables entry. It is a local copy of
// k8s.io/apiserver/pkg/admission/plugin/policy/validating.Variable, which is
// the type upstream's compilePolicy uses: importing that package for its three
// fields drags the whole validating-policy machinery into the wasm binary and
// costs roughly 38 MB uncompressed.
type mutationVariable struct {
	Name       string
	Expression string
}

var _ plugincel.NamedExpressionAccessor = &mutationVariable{}

func (v *mutationVariable) GetName() string       { return v.Name }
func (v *mutationVariable) GetExpression() string { return v.Expression }
func (v *mutationVariable) ReturnTypes() []*cel.Type {
	return []*cel.Type{cel.AnyType, cel.DynType}
}

func namedVariables(variables []admissionregistrationv1.Variable) []plugincel.NamedExpressionAccessor {
	if len(variables) == 0 {
		return nil
	}
	accessors := make([]plugincel.NamedExpressionAccessor, len(variables))
	for i, variable := range variables {
		accessors[i] = &mutationVariable{Name: variable.Name, Expression: variable.Expression}
	}
	return accessors
}

// decodeUnstructured parses arbitrary object YAML through decodeObjectInput, so
// this mode sees exactly what the vap and webhook modes do. The playground
// accepts custom resources with no compiled-in Go type, so the object stays
// unstructured throughout; decodeObjectInput's types are the ones
// unstructured.Unstructured requires.
func decodeUnstructured(input []byte) (*unstructured.Unstructured, error) {
	decoded, err := decodeObjectInput(input)
	if err != nil {
		return nil, err
	}
	if len(decoded) == 0 {
		return nil, nil
	}
	return &unstructured.Unstructured{Object: decoded}, nil
}

// requestKind takes the group/version/kind from the Request tab where it is
// filled in, falling back to the object's own.
func requestKind(kind GVKType, fallback schema.GroupVersionKind) schema.GroupVersionKind {
	if kind.Kind == "" && kind.Version == "" && kind.Group == "" {
		return fallback
	}
	return schema.GroupVersionKind{Group: kind.Group, Version: kind.Version, Kind: kind.Kind}
}

// decodeNamespaceObject parses the Namespace tab into the typed Namespace that
// the mutation CEL environment binds as `namespaceObject`.
//
// The nil guard deliberately matches deserializeNamespace (k8s/namespace.go),
// which feeds the same tab to the matchCondition environment: nil in, nil out,
// but an *empty* input still yields a zero-valued namespace. That distinction
// is load-bearing, because cmd/wasm/main.go sends []byte("") for a blank tab,
// never nil. Guarding on emptiness here instead would leave the two
// environments disagreeing about the same blank tab -- a matchCondition would
// see `namespaceObject.metadata` while a mutation in the same policy would not.
func decodeNamespaceObject(input []byte) (*corev1.Namespace, error) {
	if input == nil {
		return nil, nil
	}
	namespace := &corev1.Namespace{}
	if err := sigsyaml.Unmarshal(input, namespace); err != nil {
		return nil, fmt.Errorf("failed to decode input for the namespace: %w", err)
	}
	return namespace, nil
}

// marshalObjectYAML serializes a patched object for display. sigs.k8s.io/yaml
// routes through encoding/json, and every object reaching here is an
// *unstructured.Unstructured, which marshals itself -- so no intermediate
// conversion to map[string]any is needed.
func marshalObjectYAML(object runtime.Object) (string, error) {
	out, err := sigsyaml.Marshal(object)
	if err != nil {
		return "", fmt.Errorf("failed to serialize the mutated object: %w", err)
	}
	return string(out), nil
}

// requestResource takes the resource from the Request tab when it is filled in,
// and otherwise guesses the plural from the kind. The playground has no
// discovery to resolve a kind to its resource, and the value only affects what
// `request.resource` and authorizer resource checks observe. Fill in the
// Request tab's `resource` when the guess is wrong.
func requestResource(request *AdmissionRequest, gvk schema.GroupVersionKind) schema.GroupVersionResource {
	if request.Resource.Resource != "" {
		return schema.GroupVersionResource{
			Group:    request.Resource.Group,
			Version:  request.Resource.Version,
			Resource: request.Resource.Resource,
		}
	}
	return schema.GroupVersionResource{
		Group:    gvk.Group,
		Version:  gvk.Version,
		Resource: guessResource(gvk.Kind),
	}
}

// guessResource applies the usual English pluralization Kubernetes uses for
// resource names: NetworkPolicy -> networkpolicies, Ingress -> ingresses,
// Deployment -> deployments. Kinds that are already plural (Endpoints) are left
// alone.
func guessResource(kind string) string {
	lower := strings.ToLower(kind)
	switch {
	case lower == "":
		return ""
	case lower == "endpoints":
		// The one built-in kind whose name is already plural. Kubernetes keeps
		// the same exception, as a list of whole names rather than a rule --
		// a kind ending in "s" is otherwise far more likely to be a singular
		// like ComponentStatus than a plural like this one.
		return lower
	case strings.HasSuffix(lower, "s"), strings.HasSuffix(lower, "x"),
		strings.HasSuffix(lower, "z"), strings.HasSuffix(lower, "ch"),
		strings.HasSuffix(lower, "sh"):
		return lower + "es"
	case strings.HasSuffix(lower, "y") && len(lower) > 1 && !isVowel(lower[len(lower)-2]):
		return lower[:len(lower)-1] + "ies"
	default:
		return lower + "s"
	}
}

func isVowel(c byte) bool {
	return strings.IndexByte("aeiou", c) >= 0
}

func admissionOperation(operation string) admission.Operation {
	switch strings.ToUpper(operation) {
	case string(admission.Update):
		return admission.Update
	case string(admission.Delete):
		return admission.Delete
	case string(admission.Connect):
		return admission.Connect
	default:
		return admission.Create
	}
}

func operationOptions(operation admission.Operation) runtime.Object {
	switch operation {
	case admission.Update:
		return &metav1.UpdateOptions{}
	case admission.Delete:
		return &metav1.DeleteOptions{}
	default:
		return &metav1.CreateOptions{}
	}
}

func requestUser(request *AdmissionRequest) user.Info {
	return &user.DefaultInfo{
		Name:   request.UserInfo.Username,
		UID:    request.UserInfo.UID,
		Groups: request.UserInfo.Groups,
		// Clone so a later edit of the returned Info cannot reach back into the
		// decoded request. maps.Clone(nil) is nil, which is what user.Info
		// expects for "no extra".
		Extra: maps.Clone(request.UserInfo.Extra),
	}
}
