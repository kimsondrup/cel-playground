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

//go:build oracle

package oracle

import (
	"context"
	"fmt"

	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"k8s.io/apiserver/pkg/admission"
	celplugin "k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/admission/plugin/policy/mutating"
	"k8s.io/apiserver/pkg/admission/plugin/policy/mutating/patch"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/matchconditions"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/cel/environment"
	clientgoapplyconfigurations "k8s.io/client-go/applyconfigurations"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
)

// MutatingCosts is the exact CEL runtime cost of evaluating one
// MutatingAdmissionPolicy against one request.
//
// Unlike a ValidatingAdmissionPolicy, every mutation is handed a FRESH
// celconfig.RuntimeCELCostBudget: mutating/dispatcher.go calls
//
//	patcher.Patch(ctx, patchRequest, celconfig.RuntimeCELCostBudget)
//
// inside the per-mutation loop, with the constant, not a running remainder.
// So a policy is rejected for cost only when a SINGLE mutation overruns
// 10,000,000, never when the mutations together do. MatchConditions get their
// own 2,500,000 from inside matchconditions.Matcher, as they do for validating.
type MutatingCosts struct {
	MatchConditions int64
	// Mutations is one entry per spec.mutations entry, in spec order.
	Mutations []int64
}

func (c MutatingCosts) Total() int64 {
	t := c.MatchConditions
	for _, m := range c.Mutations {
		t += m
	}
	return t
}

func (c MutatingCosts) String() string {
	return fmt.Sprintf("matchConditions=%d mutations=%v (total=%d)", c.MatchConditions, c.Mutations, c.Total())
}

// MutatingEvaluator is the compiled form of a MutatingAdmissionPolicy plus the
// cost meters wired into each mutation's CEL evaluator.
type MutatingEvaluator struct {
	Matcher  matchconditions.Matcher
	Mutators []patch.Patcher
	Compiler *celplugin.CompositedCompiler
	// spent[i] is written by the recording wrapper each time mutation i is
	// evaluated. It holds the cost of the LAST evaluation, which is what a
	// reinvoked mutation makes ambiguous -- read it after each Patch, not once
	// at the end.
	spent []*int64
	Err   error
}

// CompileMutatingPolicy is a reproduction of the unexported
// mutating.compilePolicy in k8s.io/apiserver@v0.36.2
// (pkg/admission/plugin/policy/mutating/compilation.go), built entirely out of
// exported API, with one addition: every MutatingEvaluator is wrapped so the
// remaining cost budget it reports is captured.
//
// The pieces that mirror upstream exactly:
//
//   - one plugincel.NewCompositedCompiler over
//     environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion())
//   - opts = {HasParams: spec.paramKind != nil, HasAuthorizer: true}
//   - matchConditions compile with those same opts (no HasPatchTypes)
//   - the mutations compile with opts PLUS HasPatchTypes: true, which is what
//     puts Object / Object.spec / JSONPatch / jsonpatch.escapeKey in scope
//   - everything uses environment.StoredExpressions
//   - a mutation whose patchType has a nil body contributes NO patcher. The
//     dispatcher treats len(Mutators) != len(Mutations) as an internal error,
//     so registry validation is presumably what stops such a policy being
//     stored; that has not been tested here.
func CompileMutatingPolicy(policy *admissionregistrationv1.MutatingAdmissionPolicy) MutatingEvaluator {
	opts := celplugin.OptionalVariableDeclarations{HasParams: policy.Spec.ParamKind != nil, HasAuthorizer: true}
	compiler, err := celplugin.NewCompositedCompiler(environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion()))
	if err != nil {
		return MutatingEvaluator{Err: fmt.Errorf("initializing the CEL compiler: %w", err)}
	}
	compiler.CompileAndStoreVariables(convertMutatingVariables(policy.Spec.Variables), opts, environment.StoredExpressions)

	var matcher matchconditions.Matcher
	if mc := policy.Spec.MatchConditions; len(mc) > 0 {
		accessors := make([]celplugin.ExpressionAccessor, len(mc))
		for i := range mc {
			accessors[i] = (*matchconditions.MatchCondition)(&mc[i])
		}
		matcher = matchconditions.NewMatcher(
			compiler.CompileCondition(accessors, opts, environment.StoredExpressions),
			policy.Spec.FailurePolicy, "policy", "validate", policy.Name)
	}

	patchOptions := opts
	patchOptions.HasPatchTypes = true

	out := MutatingEvaluator{Matcher: matcher, Compiler: compiler}
	for _, m := range policy.Spec.Mutations {
		var evaluator celplugin.MutatingEvaluator
		var build func(celplugin.MutatingEvaluator) patch.Patcher
		switch m.PatchType {
		case admissionregistrationv1.PatchTypeJSONPatch:
			if m.JSONPatch == nil {
				continue
			}
			evaluator = compiler.CompileMutatingEvaluator(&patch.JSONPatchCondition{Expression: m.JSONPatch.Expression}, patchOptions, environment.StoredExpressions)
			build = patch.NewJSONPatcher
		case admissionregistrationv1.PatchTypeApplyConfiguration:
			if m.ApplyConfiguration == nil {
				continue
			}
			evaluator = compiler.CompileMutatingEvaluator(&patch.ApplyConfigurationCondition{Expression: m.ApplyConfiguration.Expression}, patchOptions, environment.StoredExpressions)
			build = patch.NewApplyConfigurationPatcher
		default:
			continue
		}
		meter := new(int64)
		out.spent = append(out.spent, meter)
		out.Mutators = append(out.Mutators, build(&costRecordingEvaluator{MutatingEvaluator: evaluator, spent: meter}))
	}
	return out
}

// costRecordingEvaluator is a plugincel.MutatingEvaluator that remembers what
// the wrapped evaluator charged.
//
// This is the whole trick behind exact costs for mutations. patch.Patcher.Patch
// takes a budget and returns only the object: the remaining budget the
// evaluator hands back is dropped on the floor inside jsonPatcher /
// applyConfigPatcher. But both patchers are constructed from a
// plugincel.MutatingEvaluator interface value, so a decorator sitting in that
// slot sees the remainder on the way past. One evaluation, exact cost, real
// upstream patch semantics.
type costRecordingEvaluator struct {
	celplugin.MutatingEvaluator
	spent *int64
}

func (c *costRecordingEvaluator) ForInput(ctx context.Context, versionedAttr *admission.VersionedAttributes, request *admissionv1.AdmissionRequest, optionalVars celplugin.OptionalVariableBindings, namespace *corev1.Namespace, budget int64) (celplugin.EvaluationResult, int64, error) {
	res, remaining, err := c.MutatingEvaluator.ForInput(ctx, versionedAttr, request, optionalVars, namespace, budget)
	if remaining >= 0 {
		*c.spent = budget - remaining
	}
	return res, remaining, err
}

func convertMutatingVariables(in []admissionregistrationv1.Variable) []celplugin.NamedExpressionAccessor {
	out := make([]celplugin.NamedExpressionAccessor, len(in))
	for i, v := range in {
		out[i] = &mutating.Variable{Name: v.Name, Expression: v.Expression}
	}
	return out
}

// MutationResult is what one in-process mutation run produced.
type MutationResult struct {
	// Object is the mutated object, or the input object when nothing matched.
	Object *unstructured.Unstructured
	// Matched is false when matchConditions skipped the policy.
	Matched bool
	// PerMutationError[i] is the error mutation i produced, nil if it applied.
	// The dispatcher's behaviour on a non-StatusError is to record it and
	// CONTINUE to the next mutation, which is reproduced here.
	PerMutationError []error
	Costs            MutatingCosts
}

// MutateInProcess runs a MutatingAdmissionPolicy's mutations against a request
// with upstream's own patchers, and reports the exact CEL cost of each.
//
// It reproduces mutating/dispatcher.go's per-invocation inner loop: mutations
// in spec order, each fed the output of the previous one, each given a fresh
// full cost budget, an error in one recorded and skipped rather than aborting.
// It does NOT reproduce reinvocation, which is a property of the whole
// admission chain rather than of one policy (see TestMAPReinvocation).
//
// typeConverter is required for applyConfiguration mutations. Supply
// StaticTypeConverter() for built-in kinds.
func MutateInProcess(ctx context.Context, policy *admissionregistrationv1.MutatingAdmissionPolicy, req InProcessRequest, typeConverter managedfields.TypeConverter) (MutationResult, error) {
	evaluator := CompileMutatingPolicy(policy)
	if evaluator.Err != nil {
		return MutationResult{}, evaluator.Err
	}
	if len(evaluator.Mutators) == 0 {
		return MutationResult{}, fmt.Errorf("policy %q compiled to no mutators", policy.Name)
	}

	versionedAttr, gvr, err := req.attributes()
	if err != nil {
		return MutationResult{}, err
	}
	if evaluator.Compiler != nil {
		ctx = evaluator.Compiler.CreateContext(ctx)
	}
	authz := req.Authorizer
	if authz == nil {
		authz = denyAllAuthorizer{}
	}
	var params runtime.Object
	if req.Params != nil {
		params = req.Params
	}
	bindings := celplugin.OptionalVariableBindings{VersionedParams: params, Authorizer: authz}

	out := MutationResult{Matched: true}

	if evaluator.Matcher != nil {
		m := evaluator.Matcher.Match(ctx, versionedAttr, params, authz)
		if m.Error != nil {
			return out, fmt.Errorf("matchConditions: %w", m.Error)
		}
		if !m.Matches {
			out.Matched = false
			out.Object = req.Object
			return out, nil
		}
	}

	oi := admission.NewObjectInterfacesFromScheme(clientgoscheme.Scheme)
	budget := int64(celconfig.RuntimeCELCostBudget)
	for i, patcher := range evaluator.Mutators {
		r := patch.Request{
			MatchedResource:     gvr,
			VersionedAttributes: versionedAttr,
			ObjectInterfaces:    oi,
			OptionalVariables:   bindings,
			Namespace:           req.Namespace,
			TypeConverter:       typeConverter,
		}
		// Upstream passes the CONSTANT here, not a remainder: every mutation
		// gets the whole budget back.
		newObj, err := patcher.Patch(ctx, r, budget)
		out.Costs.Mutations = append(out.Costs.Mutations, *evaluator.spent[i])
		if err != nil {
			out.PerMutationError = append(out.PerMutationError, err)
			continue
		}
		out.PerMutationError = append(out.PerMutationError, nil)
		versionedAttr.Dirty = true
		versionedAttr.VersionedObject = newObj
	}

	if u, ok := versionedAttr.VersionedObject.(*unstructured.Unstructured); ok {
		out.Object = u
	} else if versionedAttr.VersionedObject != nil {
		m, cerr := runtime.DefaultUnstructuredConverter.ToUnstructured(versionedAttr.VersionedObject)
		if cerr != nil {
			return out, cerr
		}
		out.Object = &unstructured.Unstructured{Object: m}
	}
	return out, nil
}

// StaticTypeConverter is a managedfields.TypeConverter covering every built-in
// Kubernetes kind, built from client-go's generated apply configurations. No
// cluster, no /openapi/v3 fetch, no network -- which is what makes an
// in-process mutating oracle (and a wasm build of one) possible at all.
//
// It is NOT what a real apiserver uses. mutating.NewPlugin passes
// patch.NewTypeConverterManager(nil, client.Discovery().OpenAPIV3()), i.e. a
// nil static converter and a live OpenAPI client, so the cluster derives its
// converter from the served schema and can serve CRDs too. The two agree for
// built-in kinds because both ultimately carry the same
// listType/listMapKey/atomic markers.
func StaticTypeConverter() managedfields.TypeConverter {
	return clientgoapplyconfigurations.NewTypeConverter(clientgoscheme.Scheme)
}

// ApplySMD is a thin wrapper over upstream's exported
// patch.ApplyStructuredMergeDiff, so a test can compare two type converters on
// the exact merge an applyConfiguration mutation performs.
func ApplySMD(tc managedfields.TypeConverter, original, patchObj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	out, err := patch.ApplyStructuredMergeDiff(tc, original, patchObj)
	if err != nil {
		return nil, err
	}
	u, ok := out.(*unstructured.Unstructured)
	if !ok {
		return nil, fmt.Errorf("unexpected result type %T", out)
	}
	return u, nil
}
