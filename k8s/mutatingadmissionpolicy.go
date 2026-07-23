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
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
//     patch types are supported. Unlike the apiserver, which aborts the policy
//     on the first failing mutation, a failing mutation here is reported and
//     the remaining ones still run against the last good object, so one broken
//     expression does not hide the rest.
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

	var mutations []*EvalMutationResult
	var finalObject, diff string
	var mutationCost uint64
	var warnings []string

	if matchConditions && len(celInfo.mutations) > 0 {
		// Force the display-side variables now: they are lazily bound, and a
		// variable only referenced from a mutation expression would otherwise
		// never be evaluated by this environment.
		for _, name := range variableNames {
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
			mutationCost, warnings = run.cost, run.warnings
		}
	}

	// The mutation cost already includes the composited re-evaluation of
	// spec.variables, so the display-side evaluation above is not added again;
	// it exists only to surface the values.
	cost := calculateEvalResponsesCost(matchConditionsEvals)
	if len(mutations) > 0 {
		cost += mutationCost
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
		return convertMAPV1Beta1(resource), nil
	case *admissionregistrationv1alpha1.MutatingAdmissionPolicy:
		return convertMAPV1Alpha1(resource), nil
	default:
		return nil, fmt.Errorf("expected a MutatingAdmissionPolicy, got %T", deser)
	}
}

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
	name := firstNonEmpty(request.Name, object.GetName())
	objectNamespace := firstNonEmpty(request.Namespace, object.GetNamespace())
	requestGVK := requestKind(request.Kind, gvk)
	attributeGVK := requestGVK
	if request.RequestKind != nil {
		attributeGVK = requestKind(*request.RequestKind, requestGVK)
	}

	operation := admissionOperation(request.Operation)
	attributes := admission.NewAttributesRecord(
		object, oldObject, attributeGVK,
		objectNamespace, name, gvr,
		request.SubResource, operation, operationOptions(operation),
		request.DryRun != nil && *request.DryRun,
		requestUser(request),
	)
	versionedAttributes := &admission.VersionedAttributes{
		Attributes:         attributes,
		VersionedKind:      gvk,
		VersionedObject:    object,
		VersionedOldObject: oldObject,
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

	bindings := plugincel.OptionalVariableBindings{
		Authorizer: &mutationAuthorizer{config: authorizer},
	}
	objectInterfaces := admission.NewObjectInterfacesFromScheme(scheme.Scheme)
	typeConverter, schemaBacked := typeConverterFor(gvk)

	// Only ApplyConfiguration consults the type converter; JSONPatch never does,
	// so a JSONPatch-only policy is unaffected by a missing schema and must not
	// be warned about.
	var warnings []string
	if !schemaBacked && hasApplyConfiguration(policy) {
		warnings = append(warnings, fmt.Sprintf(
			"No embedded OpenAPI schema for %s, so ApplyConfiguration merges are approximate: "+
				"lists are treated as atomic, and a mutation that adds a list entry replaces the "+
				"whole list instead of merging it by key. Schemas are embedded for %s.",
			gvk.GroupVersion().String(), strings.Join(embeddedGroupVersions(), ", ")))
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

		evaluator, patcher, err := compileMutation(compiler, mutation, patchDeclarations)
		if err != nil {
			setMutationError(result, err)
			continue
		}

		// patch.Patcher.Patch does not report cost, so the expression is first
		// evaluated directly to measure it. CEL is side-effect free, so the
		// second evaluation inside Patch produces the same value.
		//
		// Each mutation gets the full cost budget, the way the apiserver's
		// dispatcher hands celconfig.RuntimeCELCostBudget to every Patch call;
		// the budget is per expression, not per policy.
		if compileErrs := evaluator.CompilationErrors(); len(compileErrs) > 0 {
			setMutationError(result, errorsJoin(compileErrs))
			continue
		}
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

	run := &mutationRun{results: results, cost: totalCost, warnings: warnings}
	if !mutated {
		// Nothing was applied, so there is no "final object" to show. Returning
		// the input here would present a re-serialized copy of what the user
		// typed as though it were a result.
		return run, nil
	}
	// The per-mutation objects above are a debugging trace the API itself does
	// not have; this is the object admission would actually hand on. Reported
	// even when a single mutation's output already equals it, since it is the
	// one result that answers what the cluster would store.
	run.finalObject = currentYAML
	run.diff = unifiedDiff(originalYAML, currentYAML, "object", "mutated")
	return run, nil
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

func errorsJoin(errs []error) error {
	messages := make([]string, 0, len(errs))
	for _, err := range errs {
		messages = append(messages, err.Error())
	}
	return fmt.Errorf("%s", strings.Join(messages, "; "))
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

// decodeUnstructured parses arbitrary object YAML. The playground accepts any
// resource, including custom resources with no compiled-in Go type, so the
// object is kept unstructured throughout.
//
// It uses the same faithful two-step decode as decodeObjectInput
// (sigs.k8s.io/yaml.YAMLToJSON followed by apimachinery's util/json), which is
// precisely what a real cluster does: YAML 1.1 coercion of bare
// `on`/`off`/`yes`/`no` keys and values (including the `on`/`yes` key collision
// that drops an annotation, exactly as the apiserver drops it) and int64/float64
// numbers. That matches the types unstructured.Unstructured requires
// (int64/float64/string/bool/nil and slices/maps of those) and makes the mutated
// object shown to the user match the one a cluster would store.
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
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
func decodeNamespaceObject(input []byte) (*corev1.Namespace, error) {
	if len(strings.TrimSpace(string(input))) == 0 {
		return nil, nil
	}
	namespace := &corev1.Namespace{}
	if err := sigsyaml.Unmarshal(input, namespace); err != nil {
		return nil, fmt.Errorf("failed to decode input for the namespace: %w", err)
	}
	return namespace, nil
}

func marshalObjectYAML(object runtime.Object) (string, error) {
	content, err := runtime.DefaultUnstructuredConverter.ToUnstructured(object)
	if err != nil {
		return "", fmt.Errorf("failed to convert the mutated object: %w", err)
	}
	out, err := sigsyaml.Marshal(content)
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
	case strings.HasSuffix(lower, "s"), strings.HasSuffix(lower, "x"),
		strings.HasSuffix(lower, "z"), strings.HasSuffix(lower, "ch"),
		strings.HasSuffix(lower, "sh"):
		if strings.HasSuffix(lower, "ss") || !strings.HasSuffix(lower, "s") {
			return lower + "es"
		}
		// Already plural, e.g. Endpoints.
		return lower
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
	info := &user.DefaultInfo{
		Name:   request.UserInfo.Username,
		UID:    request.UserInfo.UID,
		Groups: request.UserInfo.Groups,
	}
	if len(request.UserInfo.Extra) > 0 {
		info.Extra = map[string][]string{}
		for key, values := range request.UserInfo.Extra {
			info.Extra[key] = values
		}
	}
	return info
}
