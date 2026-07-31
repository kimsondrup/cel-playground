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
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	celplugin "k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/admission/plugin/policy/validating"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/matchconditions"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/cel/environment"
)

// CompilePolicy is a line-for-line reproduction of the unexported
// validating.compilePolicy in k8s.io/apiserver@v0.36.2
// (pkg/admission/plugin/policy/validating/plugin.go, ~line 147), built entirely
// out of exported API. It is the single most load-bearing function in this
// package: everything downstream inherits upstream's exact evaluation
// semantics, including the two different OptionalVariableDeclarations upstream
// uses for the policy body versus messageExpression.
//
// Keeping this in sync with upstream is the maintenance cost of the oracle. The
// pieces that must be mirrored are:
//
//   - the env set is environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion()),
//     NOT a hardcoded minor. With apiserver v0.36.2 that default is 1.35, one
//     minor behind the library version.
//   - matchConditions and validations both compile with HasAuthorizer: true and
//     with `variables` declared, so the *compiler* would accept variables.x in a
//     matchCondition; only registry validation rejects it (see TestAcceptance).
//   - messageExpression alone compiles with HasAuthorizer: false.
//   - everything uses environment.StoredExpressions, i.e. the permissive
//     "already persisted" mode, not NewExpressions.
func CompilePolicy(policy *admissionregistrationv1.ValidatingAdmissionPolicy) validating.Validator {
	parts := compileParts(policy)
	if parts.err != nil {
		return validating.NewValidator(nil, nil, nil, nil, policy.Spec.FailurePolicy, parts.err)
	}
	return validating.NewValidator(
		parts.validations,
		parts.matcher,
		parts.auditAnnotations,
		parts.messageExpressions,
		policy.Spec.FailurePolicy,
		nil,
	)
}

// compiledParts holds the four condition evaluators upstream's compilePolicy
// builds, kept separately so the cost accounting below can address each batch.
type compiledParts struct {
	validations        celplugin.ConditionEvaluator
	matchConditions    celplugin.ConditionEvaluator
	auditAnnotations   celplugin.ConditionEvaluator
	messageExpressions celplugin.ConditionEvaluator
	matcher            matchconditions.Matcher
	err                error
}

func compileParts(policy *admissionregistrationv1.ValidatingAdmissionPolicy) compiledParts {
	hasParam := policy.Spec.ParamKind != nil
	optionalVars := celplugin.OptionalVariableDeclarations{HasParams: hasParam, HasAuthorizer: true}
	expressionOptionalVars := celplugin.OptionalVariableDeclarations{HasParams: hasParam, HasAuthorizer: false}
	failurePolicy := policy.Spec.FailurePolicy

	compositionEnvTemplate := environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion())
	filterCompiler, err := celplugin.NewCompositedCompiler(compositionEnvTemplate)
	if err != nil {
		return compiledParts{err: err}
	}
	filterCompiler.CompileAndStoreVariables(convertVariables(policy.Spec.Variables), optionalVars, environment.StoredExpressions)

	var parts compiledParts
	if matchConditions := policy.Spec.MatchConditions; len(matchConditions) > 0 {
		accessors := make([]celplugin.ExpressionAccessor, len(matchConditions))
		for i := range matchConditions {
			accessors[i] = (*matchconditions.MatchCondition)(&matchConditions[i])
		}
		parts.matchConditions = filterCompiler.CompileCondition(accessors, optionalVars, environment.StoredExpressions)
		parts.matcher = matchconditions.NewMatcher(parts.matchConditions, failurePolicy, "policy", "validate", policy.Name)
	}
	parts.validations = filterCompiler.CompileCondition(convertValidations(policy.Spec.Validations), optionalVars, environment.StoredExpressions)
	parts.auditAnnotations = filterCompiler.CompileCondition(convertAuditAnnotations(policy.Spec.AuditAnnotations), optionalVars, environment.StoredExpressions)
	parts.messageExpressions = filterCompiler.CompileCondition(convertMessageExpressions(policy.Spec.Validations), expressionOptionalVars, environment.StoredExpressions)
	return parts
}

func convertVariables(in []admissionregistrationv1.Variable) []celplugin.NamedExpressionAccessor {
	out := make([]celplugin.NamedExpressionAccessor, len(in))
	for i, v := range in {
		out[i] = &validating.Variable{Name: v.Name, Expression: v.Expression}
	}
	return out
}

func convertValidations(in []admissionregistrationv1.Validation) []celplugin.ExpressionAccessor {
	out := make([]celplugin.ExpressionAccessor, len(in))
	for i, v := range in {
		out[i] = &validating.ValidationCondition{Expression: v.Expression, Message: v.Message, Reason: v.Reason}
	}
	return out
}

func convertMessageExpressions(in []admissionregistrationv1.Validation) []celplugin.ExpressionAccessor {
	out := make([]celplugin.ExpressionAccessor, len(in))
	for i, v := range in {
		if v.MessageExpression != "" {
			out[i] = &validating.MessageExpressionCondition{MessageExpression: v.MessageExpression}
		}
	}
	return out
}

func convertAuditAnnotations(in []admissionregistrationv1.AuditAnnotation) []celplugin.ExpressionAccessor {
	out := make([]celplugin.ExpressionAccessor, len(in))
	for i, a := range in {
		out[i] = &validating.AuditAnnotationCondition{Key: a.Key, ValueExpression: a.ValueExpression}
	}
	return out
}

// InProcessRequest is everything the playground's vap tab collects, in the
// shape validating.Validator wants.
type InProcessRequest struct {
	// Object and OldObject are the decoded object/oldObject tabs. Either may be
	// nil (CREATE has no oldObject, DELETE has no object).
	Object    *unstructured.Unstructured
	OldObject *unstructured.Unstructured
	// Namespace is the namespaceObject tab; nil for cluster-scoped requests.
	Namespace *corev1.Namespace
	// Params is the params tab; the playground has none yet, so normally nil.
	Params *unstructured.Unstructured

	Operation admission.Operation
	// UserInfo defaults to a plain authenticated user when nil.
	UserInfo user.Info
	// Authorizer defaults to one that denies everything when nil.
	Authorizer authorizer.Authorizer
	// Budget defaults to celconfig.RuntimeCELCostBudget.
	Budget int64

	// Resource and Kind override the GVR/GVK derived from Object. Set them for
	// DELETE, where there is no object to derive from.
	Resource *schema.GroupVersionResource
	Kind     *schema.GroupVersionKind
	// Subresource is "" for the main resource.
	Subresource string

	// ResourceName and ResourceNamespace override the name and namespace the
	// attributes carry, which otherwise come from the object. The playground
	// lets its Request tab say something the object does not, so the oracle has
	// to be able to say it too.
	ResourceName      string
	ResourceNamespace string
}

// denyAllAuthorizer stands in for a cluster's authorizer when the caller did
// not supply one. It deliberately denies rather than erroring, so that
// authorizer expressions evaluate to a decision instead of blowing up.
type denyAllAuthorizer struct{}

func (denyAllAuthorizer) Authorize(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
	return authorizer.DecisionDeny, "oracle: no authorizer configured", nil
}

// Evaluate runs the policy against the request with upstream's own validator
// and returns the raw ValidateResult. This is the in-process oracle: no etcd,
// no apiserver, no network -- but the exact code path a cluster takes once a
// policy has been admitted and matched.
func Evaluate(ctx context.Context, policy *admissionregistrationv1.ValidatingAdmissionPolicy, req InProcessRequest) (validating.ValidateResult, error) {
	validator := CompilePolicy(policy)
	if err := validator.CompileError(); err != nil {
		return validating.ValidateResult{}, fmt.Errorf("compiling policy %q: %w", policy.Name, err)
	}

	versionedAttr, gvr, err := req.attributes()
	if err != nil {
		return validating.ValidateResult{}, err
	}

	authz := req.Authorizer
	if authz == nil {
		authz = denyAllAuthorizer{}
	}
	budget := req.Budget
	if budget == 0 {
		budget = celconfig.RuntimeCELCostBudget
	}

	// versionedParams must be an untyped nil when there is no params object;
	// a typed (*unstructured.Unstructured)(nil) is not nil to the validator.
	var params runtime.Object
	if req.Params != nil {
		params = req.Params
	}
	return validator.Validate(ctx, gvr, versionedAttr, params, req.Namespace, budget, authz), nil
}

func (req InProcessRequest) attributes() (*admission.VersionedAttributes, schema.GroupVersionResource, error) {
	obj := req.Object
	oldObj := req.OldObject

	var gvk schema.GroupVersionKind
	switch {
	case req.Kind != nil:
		gvk = *req.Kind
	case obj != nil:
		gvk = obj.GroupVersionKind()
	case oldObj != nil:
		gvk = oldObj.GroupVersionKind()
	default:
		return nil, schema.GroupVersionResource{}, fmt.Errorf("request has neither object, oldObject nor an explicit Kind")
	}
	if gvk.Kind == "" {
		return nil, schema.GroupVersionResource{}, fmt.Errorf("object has no kind")
	}

	var gvr schema.GroupVersionResource
	if req.Resource != nil {
		gvr = *req.Resource
	} else {
		gvr = schema.GroupVersionResource{Group: gvk.Group, Version: gvk.Version, Resource: guessResource(gvk.Kind)}
	}

	name, namespace := "", ""
	if obj != nil {
		name, namespace = obj.GetName(), obj.GetNamespace()
	} else if oldObj != nil {
		name, namespace = oldObj.GetName(), oldObj.GetNamespace()
	}
	if req.ResourceName != "" {
		name = req.ResourceName
	}
	if req.ResourceNamespace != "" {
		namespace = req.ResourceNamespace
	}

	userInfo := req.UserInfo
	if userInfo == nil {
		userInfo = &user.DefaultInfo{Name: "oracle", UID: "oracle", Groups: []string{user.AllAuthenticated}}
	}

	op := req.Operation
	if op == "" {
		op = admission.Create
	}

	// A nil *unstructured.Unstructured stored in a runtime.Object interface is
	// NOT nil, and both admission and the CEL activation compare the interface
	// against nil to decide whether to bind `object`/`oldObject` as null. Both
	// therefore have to become untyped nils when absent.
	attr := admission.NewAttributesRecord(
		asRuntimeObject(obj), asRuntimeObject(oldObj),
		gvk, namespace, name, gvr, req.Subresource,
		op, operationOptions(op), false, userInfo,
	)

	versionedAttr := &admission.VersionedAttributes{
		Attributes:         attr,
		VersionedKind:      gvk,
		VersionedObject:    asRuntimeObject(obj),
		VersionedOldObject: asRuntimeObject(oldObj),
	}
	return versionedAttr, gvr, nil
}

func asRuntimeObject(u *unstructured.Unstructured) runtime.Object {
	if u == nil || len(u.Object) == 0 {
		return nil
	}
	return u
}

func operationOptions(op admission.Operation) runtime.Object {
	switch op {
	case admission.Create:
		return &metav1.CreateOptions{}
	case admission.Update:
		return &metav1.UpdateOptions{}
	case admission.Delete:
		return &metav1.DeleteOptions{}
	default:
		return nil
	}
}

// guessResource is the usual naive Kind -> resource pluralisation. It only has
// to be good enough for the resource string that shows up in `request.resource`
// and in matchConstraints comparisons the oracle does not perform; callers with
// a real RESTMapper should set InProcessRequest.Resource explicitly.
func guessResource(kind string) string {
	lower := strings.ToLower(kind)
	switch {
	case strings.HasSuffix(lower, "s"), strings.HasSuffix(lower, "x"), strings.HasSuffix(lower, "ch"), strings.HasSuffix(lower, "sh"):
		return lower + "es"
	case strings.HasSuffix(lower, "y"):
		return strings.TrimSuffix(lower, "y") + "ies"
	default:
		return lower + "s"
	}
}

// Costs is the exact CEL runtime cost of one policy evaluation, broken down the
// way upstream actually charges it.
//
// The budget is NOT one pot. validator.Validate spends it in three independent
// chains (pkg/admission/plugin/policy/validating/validator.go):
//
//	validations -> messageExpressions   share one RuntimeCELCostBudget (10,000,000);
//	                                    messageFilter is handed the *remaining*
//	                                    budget after the validations ran.
//	auditAnnotations                    get a FRESH RuntimeCELCostBudget --
//	                                    validator.go passes the full constant
//	                                    again, discarding what validations spent.
//	matchConditions                     get RuntimeCELCostBudgetMatchConditions
//	                                    (2,500,000), hardcoded inside the Matcher.
//
// So a policy is rejected for cost when any single chain overruns, not when the
// sum does -- and "the cost of this policy" is a vector, not a scalar. A UI that
// adds all of these into one number and compares it against 10,000,000 will
// mislead in both directions.
//
// Lazily-composited variables are charged inside whichever chain reads them,
// and each chain gets a fresh composition context, so a variable read from both
// the validations and the auditAnnotations is evaluated and charged twice.
type Costs struct {
	MatchConditions    int64
	Validations        int64
	MessageExpressions int64
	AuditAnnotations   int64
}

// ValidationChain is what the validations and messageExpressions spend against
// their shared budget.
func (c Costs) ValidationChain() int64 { return c.Validations + c.MessageExpressions }

// MinimumBudget is the smallest RuntimeCELCostBudget that lets this evaluation
// complete: the larger of the two chains that the budget parameter governs.
func (c Costs) MinimumBudget() int64 {
	if c.AuditAnnotations > c.ValidationChain() {
		return c.AuditAnnotations
	}
	return c.ValidationChain()
}

func (c Costs) String() string {
	return fmt.Sprintf("matchConditions=%d validations=%d messageExpressions=%d auditAnnotations=%d (validation chain=%d, minimum budget=%d)",
		c.MatchConditions, c.Validations, c.MessageExpressions, c.AuditAnnotations, c.ValidationChain(), c.MinimumBudget())
}

// ExactCosts reports the exact per-chain CEL runtime cost of evaluating a
// policy.
//
// Upstream never surfaces cost: not in ValidateResult, not in the
// apiserver_validating_admission_policy_* metrics, not in the policy status.
// But ConditionEvaluator.ForInput returns the remaining budget, and the
// difference from the budget handed in is exactly the integer activation.go
// charged. One call per chain, no bisection, no cluster.
func ExactCosts(ctx context.Context, policy *admissionregistrationv1.ValidatingAdmissionPolicy, req InProcessRequest) (Costs, error) {
	parts := compileParts(policy)
	if parts.err != nil {
		return Costs{}, fmt.Errorf("compiling policy %q: %w", policy.Name, parts.err)
	}

	versionedAttr, gvr, err := req.attributes()
	if err != nil {
		return Costs{}, err
	}
	authz := req.Authorizer
	if authz == nil {
		authz = denyAllAuthorizer{}
	}
	var params runtime.Object
	if req.Params != nil {
		params = req.Params
	}

	admissionRequest := celplugin.CreateAdmissionRequest(
		versionedAttr.Attributes,
		metav1.GroupVersionResource(gvr),
		metav1.GroupVersionKind(versionedAttr.VersionedKind),
	)
	ns := celplugin.CreateNamespaceObject(req.Namespace)

	// Upstream's two binding sets. Only the matchConditions and the validations
	// are given the authorizer: validator.Validate passes bindings without it to
	// both the messageExpressions and the auditAnnotations, so an audit
	// annotation that calls `authorizer` compiles and then fails at evaluation.
	withAuthz := celplugin.OptionalVariableBindings{VersionedParams: params, Authorizer: authz}
	withoutAuthz := celplugin.OptionalVariableBindings{VersionedParams: params}

	spend := func(ev celplugin.ConditionEvaluator, bindings celplugin.OptionalVariableBindings, budget int64) (int64, error) {
		if ev == nil {
			return 0, nil
		}
		_, remaining, err := ev.ForInput(ctx, versionedAttr, admissionRequest, bindings, ns, budget)
		if err != nil {
			return 0, err
		}
		if remaining < 0 {
			return 0, fmt.Errorf("evaluation exhausted the %d budget", budget)
		}
		return budget - remaining, nil
	}

	full := int64(celconfig.RuntimeCELCostBudget)
	var costs Costs

	if costs.MatchConditions, err = spend(parts.matchConditions, withAuthz, int64(celconfig.RuntimeCELCostBudgetMatchConditions)); err != nil {
		return costs, fmt.Errorf("matchConditions: %w", err)
	}
	if costs.Validations, err = spend(parts.validations, withAuthz, full); err != nil {
		return costs, fmt.Errorf("validations: %w", err)
	}
	if costs.MessageExpressions, err = spend(parts.messageExpressions, withoutAuthz, full-costs.Validations); err != nil {
		return costs, fmt.Errorf("messageExpressions: %w", err)
	}
	if costs.AuditAnnotations, err = spend(parts.auditAnnotations, withoutAuthz, full); err != nil {
		return costs, fmt.Errorf("auditAnnotations: %w", err)
	}
	return costs, nil
}

// MinimumBudget bisects the budget passed to validator.Validate to find the
// smallest value that avoids exhaustion. It exists to cross-check ExactCosts
// against the only signal a real cluster gives up (see TestCostBudgetBisect):
// the sharp boundary at which OutOfBudgetMessage appears. The two must agree.
//
// The result has a floor of 1, because InProcessRequest.Budget reads its zero
// value as "use the default". A policy whose expressions genuinely cost 0 (a
// literal `true`) therefore reports 1 here and 0 from ExactCosts; compare
// against Costs.MinimumBudget() clamped to 1.
func MinimumBudget(ctx context.Context, policy *admissionregistrationv1.ValidatingAdmissionPolicy, req InProcessRequest) (int64, error) {
	fits := func(budget int64) (bool, error) {
		r := req
		r.Budget = budget
		res, err := Evaluate(ctx, policy, r)
		if err != nil {
			return false, err
		}
		return !outOfBudget(res), nil
	}

	hi := int64(celconfig.RuntimeCELCostBudget)
	ok, err := fits(hi)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, fmt.Errorf("evaluation exceeds the full %d cost budget; not bisectable", hi)
	}
	// Evaluate() reads a zero Budget as "use the default", so the floor is 1.
	lo := int64(1)
	for lo < hi {
		mid := lo + (hi-lo)/2
		ok, err := fits(mid)
		if err != nil {
			return 0, err
		}
		if ok {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return lo, nil
}

// OutOfBudgetMessage is the exact, load-bearing string upstream produces when
// an evaluation exhausts its runtime cost budget
// (pkg/admission/plugin/cel/activation.go).
const OutOfBudgetMessage = "validation failed due to running out of cost budget, no further validation rules will be run"

func outOfBudget(res validating.ValidateResult) bool {
	for _, d := range res.Decisions {
		if strings.Contains(d.Message, OutOfBudgetMessage) {
			return true
		}
	}
	for _, a := range res.AuditAnnotations {
		if strings.Contains(a.Error, OutOfBudgetMessage) {
			return true
		}
	}
	return false
}

// FormatResult renders a ValidateResult the way a reviewer wants to read it in
// test output.
func FormatResult(res validating.ValidateResult) string {
	var b strings.Builder
	for i, d := range res.Decisions {
		fmt.Fprintf(&b, "decision[%d]: action=%s evaluation=%s reason=%q message=%q\n",
			i, d.Action, d.Evaluation, reasonString(d.Reason), d.Message)
	}
	for i, a := range res.AuditAnnotations {
		fmt.Fprintf(&b, "auditAnnotation[%d]: key=%q action=%s value=%q error=%q\n",
			i, a.Key, a.Action, a.Value, a.Error)
	}
	if b.Len() == 0 {
		return "(no decisions, no audit annotations)\n"
	}
	return b.String()
}

func reasonString(r metav1.StatusReason) string { return string(r) }
