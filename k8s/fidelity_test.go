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
