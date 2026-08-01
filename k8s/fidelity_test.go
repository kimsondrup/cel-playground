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
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// The rules in this file are the ones the evaluator mirrors from the apiserver
// and that no shipped fixture happens to exercise: which variables each batch
// binds, when a batch runs at all, and how a failure message is chosen. Each
// case names the upstream call site it pins, so that a Kubernetes bump which
// changes one of them has somewhere to fail.
//
// k8s/oracle checks the same rules against upstream's own validator and against
// a real apiserver. These are here as well because they are the half that runs
// in CI.

const fidelityObject = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: production
spec:
  replicas: 3
`

const fidelityNamespace = `
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    environment: prod
`

func evalFidelityPolicy(t *testing.T, policy string) EvalResponse {
	t.Helper()
	out, err := EvalValidatingAdmissionPolicy([]byte(policy), nil, []byte(fidelityObject), []byte(fidelityNamespace), nil, nil)
	if err != nil {
		t.Fatalf("EvalValidatingAdmissionPolicy() error: %v", err)
	}
	response := EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	return response
}

// A validation that fails takes its message from its messageExpression, and
// only falls back to the literal `message` when the expression produced nothing
// usable -- empty, multi-line, or over MaxEvaluatedMessageExpressionSizeBytes.
// With neither, the expression itself is quoted.
//
// Upstream: plugin/policy/validating/validator.go, the decision loop.
func TestFailureMessageFollowsUpstreamsFallbackChain(t *testing.T) {
	tests := []struct {
		name       string
		validation string
		want       string
	}{{
		name: "the messageExpression wins over the literal message",
		validation: `
    - expression: "false"
      message: "the literal message"
      messageExpression: "'the computed message'"`,
		want: "the computed message",
	}, {
		name: "a multi-line result is unusable and the literal message is taken",
		validation: `
    - expression: "false"
      message: "the literal message"
      messageExpression: "'first line\\nsecond line'"`,
		want: "the literal message",
	}, {
		name: "an empty result is unusable and the literal message is taken",
		validation: `
    - expression: "false"
      message: "the literal message"
      messageExpression: "'   '"`,
		want: "the literal message",
	}, {
		name: "a result over the size cap is unusable and the literal message is taken",
		validation: `
    - expression: "false"
      message: "the literal message"
      messageExpression: "'x'.repeat(5121)"`,
		want: "the literal message",
	}, {
		name: "the result is trimmed",
		validation: `
    - expression: "false"
      messageExpression: "'  padded  '"`,
		want: "padded",
	}, {
		name: "with neither, the expression is quoted",
		validation: `
    - expression: "1 == 2"`,
		want: "failed expression: 1 == 2",
	}, {
		name: "a messageExpression that fails leaves the literal message",
		validation: `
    - expression: "false"
      message: "the literal message"
      messageExpression: "object.spec.missing"`,
		want: "the literal message",
	}, {
		name: "a validation that passes has no message at all",
		validation: `
    - expression: "true"
      message: "the literal message"
      messageExpression: "'the computed message'"`,
		want: "",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := evalFidelityPolicy(t, `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: messages
spec:
  validations:`+tt.validation+"\n")
			if len(response.Validations) != 1 {
				t.Fatalf("got %d validations, want 1", len(response.Validations))
			}
			got, _ := response.Validations[0].Message.(string)
			if got != tt.want {
				t.Errorf("message = %q, want %q", got, tt.want)
			}
		})
	}
}

// A messageExpression is evaluated for every validation that declares one,
// whatever the validations decided, because the apiserver evaluates the whole
// batch before it reads any decision. It is charged for either way.
//
// Upstream: validator.go calls messageFilter.ForInput before the decision loop.
func TestMessageExpressionsRunEvenWhenTheValidationPasses(t *testing.T) {
	response := evalFidelityPolicy(t, `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: messages
spec:
  validations:
    - expression: "true"
      messageExpression: "'evaluated for ' + object.metadata.name"
`)
	if len(response.MessageExpressions) != 1 {
		t.Fatalf("got %d messageExpressions, want 1", len(response.MessageExpressions))
	}
	if got := response.MessageExpressions[0].Result; got != "evaluated for web" {
		t.Errorf("messageExpressions[0].result = %v, want the evaluated string", got)
	}
	if response.MessageExpressions[0].Cost == nil || *response.MessageExpressions[0].Cost == 0 {
		t.Errorf("messageExpressions[0] was not charged: %+v", response.MessageExpressions[0])
	}
}

// `authorizer` is not declared for a messageExpression: a message is rendered
// after the decision is made, so it may not ask new authorization questions.
//
// Upstream: compilePolicy compiles the message chain with a separate
// OptionalVariableDeclarations whose HasAuthorizer is false.
func TestAuthorizerIsNotDeclaredForAMessageExpression(t *testing.T) {
	response := evalFidelityPolicy(t, `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: authorizer-in-message
spec:
  validations:
    - expression: "false"
      messageExpression: 'authorizer.group("apps").resource("deployments").check("get").allowed() ? "a" : "b"'
`)
	if len(response.MessageExpressions) != 1 || !response.MessageExpressions[0].IsError {
		t.Fatalf("the messageExpression compiled: %+v", response.MessageExpressions)
	}
	if got := *response.MessageExpressions[0].Error; !strings.Contains(got, "undeclared reference to 'authorizer'") {
		t.Errorf("error = %q, want an undeclared reference to 'authorizer'", got)
	}
}

// `authorizer` IS declared for an audit annotation, because the annotation is
// compiled with the same declarations as the validations -- but it is not
// bound, so calling it compiles and then fails at evaluation.
//
// Upstream: validator.go passes the audit filter bindings with no Authorizer.
func TestAuthorizerIsDeclaredButUnboundForAnAuditAnnotation(t *testing.T) {
	response := evalFidelityPolicy(t, `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: authorizer-in-audit-annotation
spec:
  validations:
    - expression: "true"
  auditAnnotations:
    - key: who
      valueExpression: 'authorizer.group("apps").resource("deployments").check("get").allowed() ? "a" : "b"'
`)
	if len(response.AuditAnnotations) != 1 || !response.AuditAnnotations[0].IsError {
		t.Fatalf("the audit annotation succeeded: %+v", response.AuditAnnotations)
	}
	got := *response.AuditAnnotations[0].Error
	if strings.Contains(got, "undeclared reference") {
		t.Errorf("error = %q, want a failure at evaluation rather than at compilation", got)
	}
	if !strings.Contains(got, "authorizer") {
		t.Errorf("error = %q, want it to name authorizer", got)
	}
}

// `namespaceObject` is null while matchConditions are evaluated: the matcher
// passes no namespace, for a policy as well as for a webhook.
//
// Upstream: plugin/webhook/matchconditions/matcher.go passes nil to ForInput.
func TestNamespaceObjectIsNullInMatchConditions(t *testing.T) {
	response := evalFidelityPolicy(t, `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: namespace-in-match-condition
spec:
  matchConditions:
    - name: prod-only
      expression: "namespaceObject.metadata.labels['environment'] == 'prod'"
  validations:
    - expression: "true"
`)
	if len(response.MatchConditions) != 1 {
		t.Fatalf("got %d matchConditions, want 1", len(response.MatchConditions))
	}
	if !response.MatchConditions[0].IsError {
		t.Fatalf("the matchCondition read namespaceObject and got %v; a cluster binds no namespace there",
			response.MatchConditions[0].Result)
	}
	// The same expression in a validation, where the namespace IS bound, works.
	response = evalFidelityPolicy(t, `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: namespace-in-validation
spec:
  validations:
    - expression: "namespaceObject.metadata.labels['environment'] == 'prod'"
`)
	if len(response.Validations) != 1 || response.Validations[0].Result != true {
		t.Errorf("a validation could not read namespaceObject: %+v", response.Validations[0])
	}
}

// A matchCondition that errors stops the policy: failurePolicy=Fail rejects the
// request and failurePolicy=Ignore skips the policy, and neither runs the
// validations. Only an unambiguous false is reported as "did not match".
//
// Upstream: matchconditions/matcher.go returns a MatchResult with an Error, or
// Matches=false, once the whole list has been evaluated.
func TestAnErroringMatchConditionStopsThePolicy(t *testing.T) {
	for _, failurePolicy := range []string{"Fail", "Ignore"} {
		t.Run(failurePolicy, func(t *testing.T) {
			response := evalFidelityPolicy(t, `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: erroring-match-condition
spec:
  failurePolicy: `+failurePolicy+`
  matchConditions:
    - name: fine
      expression: "true"
    - name: broken
      expression: "object.spec.missing == 1"
  validations:
    - expression: "true"
  auditAnnotations:
    - key: k
      valueExpression: "'v'"
`)
			if len(response.MatchConditions) != 2 || !response.MatchConditions[1].IsError {
				t.Fatalf("the second matchCondition did not error: %+v", response.MatchConditions)
			}
			if len(response.Validations) != 0 {
				t.Errorf("%d validations ran after a matchCondition errored", len(response.Validations))
			}
			if len(response.AuditAnnotations) != 0 {
				t.Errorf("%d audit annotations ran after a matchCondition errored", len(response.AuditAnnotations))
			}
		})
	}
}

// Audit annotations are evaluated whatever the validations decided.
//
// Upstream: validator.go calls auditAnnotationFilter.ForInput unconditionally,
// after the decision loop.
func TestAuditAnnotationsRunWhenAValidationFailed(t *testing.T) {
	response := evalFidelityPolicy(t, `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: audit-after-failure
spec:
  validations:
    - expression: "false"
  auditAnnotations:
    - key: k
      valueExpression: "'published anyway'"
`)
	if len(response.AuditAnnotations) != 1 {
		t.Fatalf("got %d audit annotations, want 1", len(response.AuditAnnotations))
	}
	if got := response.AuditAnnotations[0].Message; got != "published anyway" {
		t.Errorf("auditAnnotations[0] = %v, want the evaluated string", got)
	}
}

// The panel's first row answers the question a policy author actually has:
// does this request get through? It follows the apiserver's rules, which
// depend on failurePolicy and on whether an expression was false or broken.
func TestAdmissionDecision(t *testing.T) {
	tests := []struct {
		name        string
		spec        string
		wantAdmit   bool
		wantMessage string
	}{{
		name:        "every validation passes",
		spec:        "  validations:\n    - expression: \"true\"",
		wantAdmit:   true,
		wantMessage: "admitted: every validation passed",
	}, {
		name:        "a validation is false",
		spec:        "  validations:\n    - expression: \"true\"\n    - expression: \"false\"\n      message: nope",
		wantAdmit:   false,
		wantMessage: "denied by validations[1]: nope",
	}, {
		name:        "a validation cannot be evaluated and failurePolicy is Fail",
		spec:        "  failurePolicy: Fail\n  validations:\n    - expression: \"object.spec.missing == 1\"",
		wantAdmit:   false,
		wantMessage: "rejected: validations[0] failed to evaluate and failurePolicy is Fail",
	}, {
		name:        "a validation cannot be evaluated and failurePolicy is Ignore",
		spec:        "  failurePolicy: Ignore\n  validations:\n    - expression: \"object.spec.missing == 1\"",
		wantAdmit:   true,
		wantMessage: "admitted: validations[0] failed to evaluate but failurePolicy is Ignore",
	}, {
		name:        "a matchCondition is false, so the policy does not apply",
		spec:        "  matchConditions:\n    - name: only-databases\n      expression: \"object.metadata.name == 'database'\"\n  validations:\n    - expression: \"false\"",
		wantAdmit:   true,
		wantMessage: `admitted: matchCondition "only-databases" is false, so the policy does not apply to this request`,
	}, {
		name:        "a matchCondition is broken and failurePolicy is Fail",
		spec:        "  failurePolicy: Fail\n  matchConditions:\n    - name: broken\n      expression: \"object.spec.missing == 1\"\n  validations:\n    - expression: \"true\"",
		wantAdmit:   false,
		wantMessage: `rejected: matchCondition "broken" failed and failurePolicy is Fail`,
	}, {
		name:        "a matchCondition is broken and failurePolicy is Ignore",
		spec:        "  failurePolicy: Ignore\n  matchConditions:\n    - name: broken\n      expression: \"object.spec.missing == 1\"\n  validations:\n    - expression: \"true\"",
		wantAdmit:   true,
		wantMessage: `admitted: matchCondition "broken" failed and failurePolicy is Ignore, so the policy is skipped`,
	}, {
		name:        "failurePolicy defaults to Fail",
		spec:        "  validations:\n    - expression: \"object.spec.missing == 1\"",
		wantAdmit:   false,
		wantMessage: "rejected: validations[0] failed to evaluate and failurePolicy is Fail",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := evalFidelityPolicy(t, "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingAdmissionPolicy\nmetadata:\n  name: decision\nspec:\n"+tt.spec+"\n")
			if len(response.Decision) != 1 {
				t.Fatalf("got %d decisions, want 1", len(response.Decision))
			}
			decision := response.Decision[0]
			if decision.Result != tt.wantAdmit {
				t.Errorf("admitted = %v, want %v (%v)", decision.Result, tt.wantAdmit, decision.Message)
			}
			if got, _ := decision.Message.(string); got != tt.wantMessage {
				t.Errorf("message = %q, want %q", got, tt.wantMessage)
			}
			if decision.IsError == tt.wantAdmit {
				t.Errorf("isError = %v for an admitted=%v decision", decision.IsError, tt.wantAdmit)
			}
		})
	}
}

// A webhook is skipped when a matchCondition is false and, when one is broken,
// its own failurePolicy decides whether the request is rejected or the webhook
// merely not called.
func TestWebhookCallDecision(t *testing.T) {
	tests := []struct {
		name        string
		webhook     string
		wantCalled  bool
		wantMessage string
	}{{
		name:        "every matchCondition is true",
		webhook:     "    matchConditions:\n      - name: always\n        expression: \"true\"",
		wantCalled:  true,
		wantMessage: "called: every matchCondition is true",
	}, {
		name:        "a matchCondition is false",
		webhook:     "    matchConditions:\n      - name: never\n        expression: \"false\"",
		wantCalled:  false,
		wantMessage: `not called: matchCondition "never" is false`,
	}, {
		name:        "a matchCondition is broken and failurePolicy is Fail",
		webhook:     "    failurePolicy: Fail\n    matchConditions:\n      - name: broken\n        expression: \"object.spec.missing == 1\"",
		wantCalled:  false,
		wantMessage: `the request is rejected without calling the webhook: matchCondition "broken" failed and failurePolicy is Fail`,
	}, {
		name:        "a matchCondition is broken and failurePolicy is Ignore",
		webhook:     "    failurePolicy: Ignore\n    matchConditions:\n      - name: broken\n        expression: \"object.spec.missing == 1\"",
		wantCalled:  false,
		wantMessage: `not called: matchCondition "broken" failed and failurePolicy is Ignore`,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configuration := "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingWebhookConfiguration\nwebhooks:\n  - name: hook.example.com\n    sideEffects: None\n    admissionReviewVersions: ['v1']\n" + tt.webhook + "\n"
			out, err := EvalWebhook([]byte(configuration), nil, []byte(fidelityObject), nil, nil)
			if err != nil {
				t.Fatalf("EvalWebhook() error: %v", err)
			}
			response := EvalResponse{}
			if err := json.Unmarshal([]byte(out), &response); err != nil {
				t.Fatalf("json.Unmarshal() error: %v", err)
			}
			if len(response.Decision) != 1 {
				t.Fatalf("got %d decisions, want 1", len(response.Decision))
			}
			decision := response.Decision[0]
			if decision.Result != tt.wantCalled {
				t.Errorf("called = %v, want %v (%v)", decision.Result, tt.wantCalled, decision.Message)
			}
			if got, _ := decision.Message.(string); got != tt.wantMessage {
				t.Errorf("message = %q, want %q", got, tt.wantMessage)
			}
		})
	}
}

// `request` is never the Request tab as typed: a cluster builds it from the
// admission attributes with plugincel.CreateAdmissionRequest, which fills in
// requestKind, requestResource, dryRun and the operation's options whatever the
// tab says. Binding the tab directly leaves all four absent, so an expression
// reading one fails here and answers on a cluster.
//
// Upstream: plugin/policy/validating/validator.go and
// plugin/webhook/matchconditions/matcher.go both call CreateAdmissionRequest.
func TestRequestIsBuiltFromTheAdmissionAttributes(t *testing.T) {
	const request = `
kind:
  group: apps
  version: v1
  kind: Deployment
resource:
  group: apps
  version: v1
  resource: deployments
name: web
namespace: production
operation: CREATE
userInfo:
  username: alice
`
	tests := []struct {
		name       string
		expression string
	}{
		{"requestKind mirrors kind", `request.requestKind.kind == 'Deployment'`},
		{"requestResource mirrors resource", `request.requestResource.resource == 'deployments'`},
		{"dryRun is always present", `request.dryRun == false`},
		{"options is present for the operation", `has(request.options)`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingAdmissionPolicy\nmetadata:\n  name: request-shape\nspec:\n  validations:\n    - expression: \"" + tt.expression + "\"\n"
			out, err := EvalValidatingAdmissionPolicy([]byte(policy), nil, []byte(fidelityObject), nil, []byte(request), nil)
			if err != nil {
				t.Fatalf("EvalValidatingAdmissionPolicy() error: %v", err)
			}
			response := EvalResponse{}
			if err := json.Unmarshal([]byte(out), &response); err != nil {
				t.Fatalf("json.Unmarshal() error: %v", err)
			}
			if len(response.Validations) != 1 {
				t.Fatalf("got %d validations, want 1", len(response.Validations))
			}
			if response.Validations[0].IsError {
				t.Fatalf("%s errored: %s", tt.expression, *response.Validations[0].Error)
			}
			if response.Validations[0].Result != true {
				t.Errorf("%s = %v, want true", tt.expression, response.Validations[0].Result)
			}
		})
	}
}

// `request.requestKind` and `request.requestResource` are what the client asked
// for and `request.kind`/`request.resource` what the policy matched at; they
// differ only under matchPolicy: Equivalent, which is the reason the fields
// exist. `request.options` carries what the client sent -- fieldManager,
// fieldValidation -- which nothing here could invent.
//
// Upstream: plugin/cel/condition.go CreateAdmissionRequest takes the attributes
// plus the matched GVR and GVK, and reads options off the attributes.
func TestRequestKeepsWhatTheTabDistinguishes(t *testing.T) {
	const request = `
kind:
  group: apps
  version: v1
  kind: Deployment
resource:
  group: apps
  version: v1
  resource: deployments
requestKind:
  group: apps
  version: v1beta1
  kind: Deployment
requestResource:
  group: apps
  version: v1beta1
  resource: deployments
name: web
namespace: production
operation: CREATE
options:
  fieldManager: kubectl-client-side-apply
  fieldValidation: Strict
userInfo:
  username: alice
`
	tests := []struct {
		name       string
		expression string
	}{
		{"kind is the matched version", `request.kind.version == 'v1'`},
		{"requestKind is the version asked for", `request.requestKind.version == 'v1beta1'`},
		{"requestResource is the version asked for", `request.requestResource.version == 'v1beta1'`},
		{"options carries what the client sent", `request.options.fieldManager == 'kubectl-client-side-apply'`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingAdmissionPolicy\nmetadata:\n  name: request-shape\nspec:\n  validations:\n    - expression: \"" + tt.expression + "\"\n"
			out, err := EvalValidatingAdmissionPolicy([]byte(policy), nil, []byte(fidelityObject), nil, []byte(request), nil)
			if err != nil {
				t.Fatalf("EvalValidatingAdmissionPolicy() error: %v", err)
			}
			response := EvalResponse{}
			if err := json.Unmarshal([]byte(out), &response); err != nil {
				t.Fatalf("json.Unmarshal() error: %v", err)
			}
			if len(response.Validations) != 1 {
				t.Fatalf("got %d validations, want 1", len(response.Validations))
			}
			if response.Validations[0].IsError {
				t.Fatalf("%s errored: %s", tt.expression, *response.Validations[0].Error)
			}
			if response.Validations[0].Result != true {
				t.Errorf("%s = %v, want true", tt.expression, response.Validations[0].Result)
			}
		})
	}
}

// A false matchCondition beats an erroring one whatever order they are in. The
// matcher evaluates every condition and collects the errors, then walks the
// results and returns "does not match" on the first false one; the errors are
// only read if nothing was false. So the policy is skipped and the request
// admitted, under either failurePolicy.
//
// Upstream: plugin/webhook/matchconditions/matcher.go, Match.
func TestAFalseMatchConditionBeatsAnErroringOne(t *testing.T) {
	conditions := "  matchConditions:\n" +
		"    - name: broken\n      expression: \"object.spec.missing == 1\"\n" +
		"    - name: never\n      expression: \"false\"\n"

	for _, failurePolicy := range []string{"Fail", "Ignore"} {
		t.Run(failurePolicy, func(t *testing.T) {
			policy := "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingAdmissionPolicy\nmetadata:\n  name: order\nspec:\n  failurePolicy: " +
				failurePolicy + "\n" + conditions + "  validations:\n    - expression: \"false\"\n"
			response := evalFidelityPolicy(t, policy)
			if len(response.Decision) != 1 {
				t.Fatalf("got %d decisions, want 1", len(response.Decision))
			}
			if response.Decision[0].Result != true {
				t.Errorf("decision = %v (%v), want admitted: a false matchCondition skips the policy",
					response.Decision[0].Result, response.Decision[0].Message)
			}
			if got, _ := response.Decision[0].Message.(string); !strings.Contains(got, `matchCondition "never" is false`) {
				t.Errorf("decision message = %q, want it to name the false condition", got)
			}
		})
	}
}

// The result panel builds its accordions in the order the JSON keys arrive, so
// the field order of EvalResponse is a UI decision and not a detail: the
// decision first because it is the answer, the warnings above the results they
// qualify, the diff before the object it summarises.
func TestEvalResponseKeyOrderIsTheReadingOrder(t *testing.T) {
	want := []string{
		"decision", "exceededBudgets", "warnings", "matchConditions",
		"validationVariables", "validations",
		"messageExpressionVariables", "messageExpressions",
		"auditAnnotationVariables", "auditAnnotations",
		"mutationVariables", "mutations",
		"diff", "finalObject", "notSimulated",
		"webhookMatchConditions", "cost",
	}
	response := reflect.TypeOf(EvalResponse{})
	var got []string
	for i := range response.NumField() {
		tag, _, _ := strings.Cut(response.Field(i).Tag.Get("json"), ",")
		got = append(got, tag)
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("the panel would render\n  %v\nand the reading order is\n  %v", got, want)
	}
}

// A matchCondition must evaluate to a bool. The compiler is given
// celgo.BoolType as the only accepted return type, so one that returns a string
// is a compilation error here and a policy the registry refuses -- not a
// condition that quietly reads as false.
//
// Upstream: matchconditions.MatchCondition's ReturnTypes, and
// plugin/cel/compile.go's "must evaluate to bool but got ...".
func TestANonBooleanMatchConditionDoesNotCompile(t *testing.T) {
	for _, expression := range []string{`"yes"`, `1`, `object.metadata.name`} {
		t.Run(expression, func(t *testing.T) {
			policy := "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingAdmissionPolicy\nmetadata:\n  name: nonbool\nspec:\n  matchConditions:\n    - name: notabool\n      expression: " + strconv.Quote(expression) + "\n  validations:\n    - expression: \"true\"\n"
			response := evalFidelityPolicy(t, policy)
			if len(response.MatchConditions) != 1 {
				t.Fatalf("got %d matchConditions, want 1", len(response.MatchConditions))
			}
			if !response.MatchConditions[0].IsError {
				t.Fatalf("%s was accepted as a matchCondition", expression)
			}
			if !strings.Contains(*response.MatchConditions[0].Error, "must evaluate to bool") {
				t.Errorf("error = %q, want the compiler's return-type message", *response.MatchConditions[0].Error)
			}
			// A policy whose matchCondition cannot compile never matches, and
			// under the default failurePolicy the request is rejected.
			if response.Decision[0].Result != false {
				t.Errorf("decision = %v, want rejected", response.Decision[0].Message)
			}
		})
	}
}
