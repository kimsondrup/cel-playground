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

package oracle_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/undistro/cel-playground/k8s"
	"github.com/undistro/cel-playground/oracle"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
	"sigs.k8s.io/yaml"
)

// parityCase is one row of the playground's own vap test table, so the two
// suites cover exactly the same corpus.
type parityCase struct {
	name       string
	policy     string
	oldObject  string
	object     string
	namespace  string
	request    string
	authorizer string
	// rejectedByRegistry marks a policy the apiserver refuses to store. Its
	// runtime cost is not comparable, because a cluster never runs it -- the
	// playground reports the refusal instead, and the test checks the real
	// apiserver agrees that it is a refusal.
	rejectedByRegistry bool
}

var parityCases = []parityCase{
	{name: "policy1", policy: "policy1.yaml", object: "updated1.yaml"},
	{name: "policy2", policy: "policy2.yaml", object: "updated2.yaml"},
	{name: "variable1", policy: "variable1 policy.yaml", object: "variable1 updated.yaml"},
	{name: "variable2", policy: "variable2 policy.yaml", object: "variable2 updated.yaml"},
	{name: "variable3", policy: "variable3 policy.yaml", object: "variable3 updated.yaml"},
	{name: "variable4", policy: "variable4 policy.yaml", object: "variable4 updated.yaml"},
	{name: "match1", policy: "match1 policy.yaml", object: "match1 updated.yaml", request: "match1 request.yaml"},
	{name: "match2", policy: "match2 policy.yaml", object: "match2 updated.yaml", request: "match2 request.yaml", rejectedByRegistry: true},
	{name: "namespace1", policy: "namespace1 policy.yaml", object: "namespace1 updated.yaml", namespace: "namespace1 namespace.yaml"},
	{name: "request1", policy: "request1 policy.yaml", object: "request1 updated.yaml", request: "request1 request.yaml"},
	{
		name: "authorizer1", policy: "authorizer1 policy.yaml", object: "authorizer1 updated.yaml",
		namespace: "authorizer1 namespace.yaml", request: "authorizer1 request.yaml", authorizer: "authorizer1 authorizer.yaml",
	},
	{
		name: "authorizer2", policy: "authorizer2 policy.yaml", object: "authorizer2 updated.yaml",
		namespace: "authorizer2 namespace.yaml", request: "authorizer2 request.yaml", authorizer: "authorizer2 authorizer.yaml",
	},
	{name: "broken1", policy: "broken1 policy.yaml", object: "broken1 updated.yaml"},
	{name: "optional_none", policy: "optional_none_dereference policy.yaml", object: "optional_none_dereference updated.yaml"},
	{name: "decode1", policy: "decode1 policy.yaml", object: "decode1 updated.yaml"},
}

// TestParityWithUpstream runs the whole shipped fixture corpus through the
// playground and through upstream's real validator and compares them chain by
// chain.
//
// Cost is the sharp end of it. The playground reports a cost per expression and
// a total, and that number is what someone uses to decide whether a policy fits
// the apiserver's budget -- so a cost that does not match what a cluster charges
// is a user-visible bug. Comparing per chain rather than in total is what
// catches a batch being evaluated the wrong number of times, which a matching
// total can hide.
func TestParityWithUpstream(t *testing.T) {
	ctx := context.Background()
	for _, tc := range parityCases {
		t.Run(tc.name, func(t *testing.T) {
			playground := runPlayground(t, tc)
			if tc.rejectedByRegistry {
				assertRejected(t, ctx, tc, playground)
				return
			}
			upstreamCosts, upstreamResult := runUpstream(t, ctx, tc)

			matchConditions, validations, auditAnnotations := playgroundChainCosts(playground)
			compare(t, "matchConditions", matchConditions, uint64(upstreamCosts.MatchConditions))
			// ExactCosts prices every chain in isolation, so it reports what the
			// validations would have cost even for a policy the matchConditions
			// skipped. A cluster charges nothing for those, and neither does the
			// playground.
			if upstreamResult.evaluated {
				compare(t, "validations and messageExpressions", validations, uint64(upstreamCosts.ValidationChain()))
				compare(t, "auditAnnotations", auditAnnotations, uint64(upstreamCosts.AuditAnnotations))
			} else {
				compare(t, "validations and messageExpressions", validations, 0)
				compare(t, "auditAnnotations", auditAnnotations, 0)
			}

			total := matchConditions + validations + auditAnnotations
			if playground.Cost == nil || *playground.Cost != total {
				t.Errorf("the reported total does not add up: sections sum to %d, response says %v", total, playground.Cost)
			}

			compareDecisions(t, playground, upstreamResult)
		})
	}
}

// assertRejected checks the two halves of "this policy cannot be created": a
// real apiserver refuses to store it, and the playground says so by reporting a
// compilation error rather than a value.
func assertRejected(t *testing.T, ctx context.Context, tc parityCase, playground k8s.EvalResponse) {
	t.Helper()
	reported := false
	for _, result := range playground.MatchConditions {
		if result.IsError {
			reported = true
		}
	}
	if !reported {
		t.Errorf("the playground evaluated %s without complaint; a cluster refuses to store it", tc.policy)
	}

	o := cluster(t)
	policy, err := oracle.ParsePolicy(string(read(t, tc.policy)))
	if err != nil {
		t.Fatalf("loading the policy: %v", err)
	}
	policy.Name = "parity-rejected-" + tc.name
	cleanup, err := o.CreatePolicyAndBinding(ctx, policy, oracle.DefaultBinding(policy.Name))
	if err == nil {
		cleanup()
		t.Fatalf("the apiserver accepted %s; the playground reports it as uncreatable", tc.policy)
	}
	if !strings.Contains(err.Error(), "undeclared reference to 'variables'") {
		t.Errorf("the apiserver refused %s for an unexpected reason: %v", tc.policy, err)
	}
}

func compare(t *testing.T, chain string, playground, upstream uint64) {
	t.Helper()
	if playground != upstream {
		t.Errorf("%s cost: playground charges %d, a cluster charges %d", chain, playground, upstream)
	}
}

// playgroundChainCosts groups the response's sections the way the apiserver
// groups its budgets: matchConditions alone, validations together with the
// messageExpressions they share a budget with, and audit annotations on their
// own.
func playgroundChainCosts(response k8s.EvalResponse) (matchConditions, validations, auditAnnotations uint64) {
	variables := func(list []*k8s.EvalVariable) uint64 {
		var total uint64
		for _, item := range list {
			if item.Cost != nil {
				total += *item.Cost
			}
		}
		return total
	}
	results := func(list []*k8s.EvalResult) uint64 {
		var total uint64
		for _, item := range list {
			if item.Cost != nil {
				total += *item.Cost
			}
		}
		return total
	}
	matchConditions = results(response.MatchConditions)
	validations = variables(response.ValidationVariables) + results(response.Validations) +
		variables(response.MessageExpressionVariables) + results(response.MessageExpressions)
	auditAnnotations = variables(response.AuditAnnotationVariables) + results(response.AuditAnnotations)
	return matchConditions, validations, auditAnnotations
}

// compareDecisions checks the failure message the playground shows against the
// one the apiserver would put in the 422. A denied validation is the only case
// where upstream produces a message at all.
func compareDecisions(t *testing.T, playground k8s.EvalResponse, upstream upstreamOutcome) {
	t.Helper()
	if !upstream.evaluated {
		if len(playground.Validations) != 0 {
			t.Errorf("the playground evaluated %d validations for a policy whose matchConditions did not match", len(playground.Validations))
		}
		return
	}
	if len(playground.Validations) != len(upstream.messages) {
		t.Fatalf("playground reports %d validations, upstream reports %d decisions", len(playground.Validations), len(upstream.messages))
	}
	for i, want := range upstream.messages {
		got := ""
		if message, ok := playground.Validations[i].Message.(string); ok {
			got = message
		}
		if want == "" {
			if got != "" {
				t.Errorf("validations[%d]: playground shows message %q, upstream admits with no message", i, got)
			}
			continue
		}
		// An evaluation error reaches the user through the error field rather
		// than the message field, and upstream words it its own way; only the
		// deny messages are compared literally.
		if playground.Validations[i].IsError {
			continue
		}
		if got != want {
			t.Errorf("validations[%d] message:\n playground: %q\n cluster:    %q", i, got, want)
		}
	}
}

type upstreamOutcome struct {
	// evaluated is false when the matchConditions stopped the policy.
	evaluated bool
	// messages is one entry per validation: the 422 message for a denial, empty
	// for an admission.
	messages []string
}

func runPlayground(t *testing.T, tc parityCase) k8s.EvalResponse {
	t.Helper()
	out, err := k8s.EvalValidatingAdmissionPolicy(
		read(t, tc.policy), read(t, tc.oldObject), read(t, tc.object),
		read(t, tc.namespace), read(t, tc.request), read(t, tc.authorizer))
	if err != nil {
		t.Fatalf("playground eval: %v", err)
	}
	response := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("decoding the playground response: %v", err)
	}
	return response
}

func runUpstream(t *testing.T, ctx context.Context, tc parityCase) (oracle.Costs, upstreamOutcome) {
	t.Helper()
	policy, err := oracle.ParsePolicy(string(read(t, tc.policy)))
	if err != nil {
		t.Fatalf("loading the policy: %v", err)
	}
	req := upstreamRequest(t, tc)

	costs, err := oracle.ExactCosts(ctx, policy, req)
	if err != nil {
		t.Fatalf("upstream costs: %v", err)
	}
	result, err := oracle.Evaluate(ctx, policy, req)
	if err != nil {
		t.Fatalf("upstream evaluate: %v", err)
	}

	outcome := upstreamOutcome{evaluated: true}
	// A policy whose matchConditions did not match produces no decisions at
	// all, which is distinguishable from one whose validations all admitted
	// only because every fixture here declares at least one validation.
	if len(result.Decisions) == 0 && len(policy.Spec.Validations) > 0 {
		outcome.evaluated = false
		return costs, outcome
	}
	for _, decision := range result.Decisions {
		outcome.messages = append(outcome.messages, decision.Message)
	}
	return costs, outcome
}

// upstreamRequest maps the playground's tabs onto the attributes upstream wants.
// The request tab is an AdmissionRequest, which is the *output* of upstream's
// request construction rather than its input, so the fields a cluster derives
// from the attributes are fed back in here.
func upstreamRequest(t *testing.T, tc parityCase) oracle.InProcessRequest {
	t.Helper()
	req := oracle.InProcessRequest{}
	if data := read(t, tc.object); len(data) > 0 {
		object, err := oracle.ParseUnstructured(string(data))
		if err != nil {
			t.Fatalf("loading the object: %v", err)
		}
		req.Object = object
	}
	if data := read(t, tc.oldObject); len(data) > 0 {
		oldObject, err := oracle.ParseUnstructured(string(data))
		if err != nil {
			t.Fatalf("loading the old object: %v", err)
		}
		req.OldObject = oldObject
	}
	if data := read(t, tc.namespace); len(data) > 0 {
		namespace := &corev1.Namespace{}
		if err := yaml.Unmarshal(data, namespace); err != nil {
			t.Fatalf("loading the namespace: %v", err)
		}
		req.Namespace = namespace
	}
	if data := read(t, tc.request); len(data) > 0 {
		admissionRequest := &admissionv1.AdmissionRequest{}
		if err := yaml.Unmarshal(data, admissionRequest); err != nil {
			t.Fatalf("loading the request: %v", err)
		}
		if admissionRequest.Operation != "" {
			req.Operation = admission.Operation(admissionRequest.Operation)
		}
		if admissionRequest.Resource.Resource != "" {
			req.Resource = &schema.GroupVersionResource{
				Group:    admissionRequest.Resource.Group,
				Version:  admissionRequest.Resource.Version,
				Resource: admissionRequest.Resource.Resource,
			}
		}
		req.Subresource = admissionRequest.SubResource
		req.ResourceName = admissionRequest.Name
		req.ResourceNamespace = admissionRequest.Namespace
		req.UserInfo = &user.DefaultInfo{
			Name:   admissionRequest.UserInfo.Username,
			UID:    admissionRequest.UserInfo.UID,
			Groups: admissionRequest.UserInfo.Groups,
			Extra:  extraValues(admissionRequest.UserInfo.Extra),
		}
	}
	if data := read(t, tc.authorizer); len(data) > 0 {
		authz, err := k8s.NewRBACAuthorizer(data)
		if err != nil {
			t.Fatalf("building the authorizer: %v", err)
		}
		req.Authorizer = authz
	} else {
		// With an empty RBAC tab the playground still answers every check, with
		// nothing allowed. Upstream's default here denies instead, which is a
		// different decision, so build the empty authorizer explicitly.
		authz, err := k8s.NewRBACAuthorizer(nil)
		if err != nil {
			t.Fatalf("building the empty authorizer: %v", err)
		}
		req.Authorizer = authz
	}
	return req
}

func extraValues(extra map[string]authenticationv1.ExtraValue) map[string][]string {
	if len(extra) == 0 {
		return nil
	}
	out := make(map[string][]string, len(extra))
	for key, value := range extra {
		out[key] = value
	}
	return out
}

func read(t *testing.T, name string) []byte {
	t.Helper()
	if name == "" {
		return nil
	}
	data, err := os.ReadFile(oracle.VAPFixture(name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return data
}

// The apiserver has two gates and they disagree about whether a matchCondition
// may read spec.variables: the registry refuses to store such a policy, while
// the runtime evaluator would happily run one. The playground shows the
// registry's answer, because that is the one an author hits first. This test
// pins the runtime half of that statement, so the claim in k8s/compiler.go
// stops being true out loud if upstream ever changes it.
func TestMatchConditionsSeeVariablesAtRuntime(t *testing.T) {
	policy, err := oracle.ParsePolicy(`
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: match-conditions-variables
spec:
  variables:
    - name: replicas
      expression: "object.spec.replicas"
  matchConditions:
    - name: big
      expression: "variables.replicas > 1"
  validations:
    - expression: "true"
`)
	if err != nil {
		t.Fatalf("parsing the policy: %v", err)
	}
	object, err := oracle.ParseUnstructured("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\nspec:\n  replicas: 3\n")
	if err != nil {
		t.Fatalf("parsing the object: %v", err)
	}
	result, err := oracle.Evaluate(context.Background(), policy, oracle.InProcessRequest{Object: object})
	if err != nil {
		t.Fatalf("upstream evaluate: %v", err)
	}
	for _, decision := range result.Decisions {
		if strings.Contains(decision.Message, "undeclared reference to 'variables'") {
			t.Fatalf("upstream's runtime evaluator rejected variables in a matchCondition: %s", decision.Message)
		}
	}
}

// An audit annotation is compiled with `authorizer` declared and evaluated with
// it unbound, so calling it compiles and then fails. Both sides must agree on
// that, and on the message. This is the case that caught ExactCosts binding an
// authorizer the apiserver does not.
func TestAuthorizerIsUnboundInAuditAnnotations(t *testing.T) {
	const source = `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: authorizer-in-audit-annotation
spec:
  validations:
    - expression: "true"
  auditAnnotations:
    - key: who
      valueExpression: 'authorizer.group("apps").resource("deployments").check("get").allowed() ? "yes" : "no"'
`
	object := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\n  namespace: default\n"

	out, err := k8s.EvalValidatingAdmissionPolicy([]byte(source), nil, []byte(object), nil, nil, nil)
	if err != nil {
		t.Fatalf("playground eval: %v", err)
	}
	playground := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &playground); err != nil {
		t.Fatalf("decoding the playground response: %v", err)
	}
	if len(playground.AuditAnnotations) != 1 || !playground.AuditAnnotations[0].IsError {
		t.Fatalf("the playground evaluated the audit annotation without complaint: %s", out)
	}

	policy, err := oracle.ParsePolicy(source)
	if err != nil {
		t.Fatalf("parsing the policy: %v", err)
	}
	obj, err := oracle.ParseUnstructured(object)
	if err != nil {
		t.Fatalf("parsing the object: %v", err)
	}
	authz, err := k8s.NewRBACAuthorizer(nil)
	if err != nil {
		t.Fatalf("building the authorizer: %v", err)
	}
	result, err := oracle.Evaluate(context.Background(), policy, oracle.InProcessRequest{Object: obj, Authorizer: authz})
	if err != nil {
		t.Fatalf("upstream evaluate: %v", err)
	}
	if len(result.AuditAnnotations) != 1 || result.AuditAnnotations[0].Error == "" {
		t.Fatalf("upstream published the audit annotation: %s", oracle.FormatResult(result))
	}
	if !strings.Contains(result.AuditAnnotations[0].Error, "authorizer") {
		t.Errorf("upstream failed for an unexpected reason: %s", result.AuditAnnotations[0].Error)
	}
}

// `params` is declared for a policy's expressions exactly when the policy
// declares spec.paramKind. The playground has no params tab, so it binds null,
// which is a state a cluster reaches whenever a binding's paramRef selects
// nothing. Both sides must compile the policy and agree on the value.
func TestParamsFollowParamKind(t *testing.T) {
	const source = `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: params-follow-paramkind
spec:
  paramKind:
    apiVersion: v1
    kind: ConfigMap
  validations:
    - expression: "params == null"
`
	object := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\n  namespace: default\n"

	out, err := k8s.EvalValidatingAdmissionPolicy([]byte(source), nil, []byte(object), nil, nil, nil)
	if err != nil {
		t.Fatalf("playground eval: %v", err)
	}
	playground := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &playground); err != nil {
		t.Fatalf("decoding the playground response: %v", err)
	}
	if len(playground.Validations) != 1 || playground.Validations[0].IsError || playground.Validations[0].Result != true {
		t.Fatalf("the playground did not evaluate `params == null` to true: %s", out)
	}

	policy, err := oracle.ParsePolicy(source)
	if err != nil {
		t.Fatalf("parsing the policy: %v", err)
	}
	obj, err := oracle.ParseUnstructured(object)
	if err != nil {
		t.Fatalf("parsing the object: %v", err)
	}
	result, err := oracle.Evaluate(context.Background(), policy, oracle.InProcessRequest{Object: obj})
	if err != nil {
		t.Fatalf("upstream evaluate: %v", err)
	}
	if len(result.Decisions) != 1 || result.Decisions[0].Evaluation != "admit" {
		t.Errorf("upstream did not admit: %s", oracle.FormatResult(result))
	}
}
