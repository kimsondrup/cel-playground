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

package k8s_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/undistro/cel-playground/k8s"
)

func vapTestfile(file string) string {
	return testfile("vap/" + file)
}

func readValidationTestData(policy, original, updated, namespace, request, authorizer string) (policyData, originalData, updatedData, namespaceData, requestData, authorizerData []byte, err error) {
	policyData, err = testdata.ReadFile(vapTestfile(policy))
	if err == nil && original != "" {
		originalData, err = testdata.ReadFile(vapTestfile(original))
	}
	if err == nil && updated != "" {
		updatedData, err = testdata.ReadFile(vapTestfile(updated))
	}
	if err == nil && namespace != "" {
		namespaceData, err = testdata.ReadFile(vapTestfile(namespace))
	}
	if err == nil && request != "" {
		requestData, err = testdata.ReadFile(vapTestfile(request))
	}
	if err == nil && authorizer != "" {
		authorizerData, err = testdata.ReadFile(vapTestfile(authorizer))
	}
	return
}

func TestValidationEval(t *testing.T) {
	tests := []struct {
		name       string
		policy     string
		orig       string
		updated    string
		namespace  string
		request    string
		authorizer string
		expected   k8s.EvalResponse
		wantErr    bool
	}{{
		name:    "test an expression which should fail",
		policy:  "policy1.yaml",
		orig:    "",
		updated: "updated1.yaml",
		expected: k8s.EvalResponse{
			Validations: []*k8s.EvalResult{{Message: "All production deployments should be HA with at least three replicas", Result: false, Cost: uint64ptr(4)}},
			Cost:        uint64ptr(4),
		},
	}, {
		name:    "test an expression which should succeed",
		policy:  "policy2.yaml",
		orig:    "",
		updated: "updated2.yaml",
		expected: k8s.EvalResponse{
			Validations: []*k8s.EvalResult{{Result: true, Cost: uint64ptr(4)}},
			Cost:        uint64ptr(4),
		},
	}, {
		name:    "test an expression with variables, expression should fail with no audit annotation",
		policy:  "variable1 policy.yaml",
		orig:    "",
		updated: "variable1 updated.yaml",
		expected: k8s.EvalResponse{
			ValidationVariables: []*k8s.EvalVariable{{
				Name:  "foo",
				Value: "default",
				Cost:  uint64ptr(6),
			}},
			Validations: []*k8s.EvalResult{{Result: false, Cost: uint64ptr(2)}},
			Cost:        uint64ptr(8),
		},
	}, {
		name:    "test an expression with variables, expression should succeed with audit annotation",
		policy:  "variable2 policy.yaml",
		orig:    "",
		updated: "variable2 updated.yaml",
		expected: k8s.EvalResponse{
			ValidationVariables: []*k8s.EvalVariable{{
				Name:  "foo",
				Value: "bar",
				Cost:  uint64ptr(11),
			}},
			Validations: []*k8s.EvalResult{{
				Result: true,
				Cost:   uint64ptr(2),
			}},
			AuditAnnotations: []*k8s.EvalResult{{
				Name:    strptr("foo-label"),
				Message: "Label for foo is set to bar",
				Cost:    uint64ptr(2),
			}},
			Cost: uint64ptr(15),
		},
	}, {
		name:    "test an expression with variables evaluating to a map, expression should succeed",
		policy:  "variable3 policy.yaml",
		orig:    "",
		updated: "variable3 updated.yaml",
		expected: k8s.EvalResponse{
			ValidationVariables: []*k8s.EvalVariable{{
				Name: "labels",
				Value: map[string]any{
					"app": "kubernetes-bootcamp",
					"foo": "bar",
				},
				Cost: uint64ptr(5),
			}},
			Validations: []*k8s.EvalResult{{Result: true, Cost: uint64ptr(2)}},
			Cost:        uint64ptr(7),
		},
	}, {
		name:    "test an expression with variables evaluating to query parameters in a URL, expression should succeed",
		policy:  "variable4 policy.yaml",
		orig:    "",
		updated: "variable4 updated.yaml",
		expected: k8s.EvalResponse{
			ValidationVariables: []*k8s.EvalVariable{{
				Name: "foo",
				Value: map[string]any{
					"query": []any{"val"},
				},
				Cost: uint64ptr(19),
			}},
			Validations: []*k8s.EvalResult{{Result: true, Cost: uint64ptr(2)}},
			Cost:        uint64ptr(21),
		},
	}, {
		name:    "test valid matchConditions, should see validations and auditAnnotations",
		policy:  "match1 policy.yaml",
		orig:    "",
		updated: "match1 updated.yaml",
		request: "match1 request.yaml",
		expected: k8s.EvalResponse{
			MatchConditions: []*k8s.EvalResult{{
				Name:   strptr("exclude-leases"),
				Result: true,
				Cost:   uint64ptr(5),
			}, {
				Name:   strptr("exclude-kubelet-requests"),
				Result: true,
				Cost:   uint64ptr(5),
			}},
			Validations: []*k8s.EvalResult{{Result: true, Cost: uint64ptr(5)}},
			AuditAnnotations: []*k8s.EvalResult{{
				Name:    strptr("test-annotation"),
				Message: "Name is kubernetes-bootcamp, namespace is default",
				Cost:    uint64ptr(9),
			}},
			Cost: uint64ptr(24),
		},
	}, {
		name:    "test invalid matchConditions, should not see validations and auditAnnotations",
		policy:  "match2 policy.yaml",
		orig:    "",
		updated: "match2 updated.yaml",
		request: "match2 request.yaml",
		expected: k8s.EvalResponse{
			MatchConditionsVariables: []*k8s.EvalVariable{{
				Name:  "isLease",
				Value: false,
				Cost:  uint64ptr(4),
			}},
			MatchConditions: []*k8s.EvalResult{{
				Name:   strptr("exclude-leases"),
				Result: true,
				Cost:   uint64ptr(2),
			}, {
				Name:   strptr("exclude-kubelet-requests"),
				Result: false,
				Cost:   uint64ptr(5),
			}},
			Cost: uint64ptr(11),
		},
	}, {
		name:      "test an expression using namespace attributes",
		policy:    "namespace1 policy.yaml",
		orig:      "",
		updated:   "namespace1 updated.yaml",
		namespace: "namespace1 namespace.yaml",
		expected: k8s.EvalResponse{
			ValidationVariables: []*k8s.EvalVariable{{
				Name:  "environment",
				Value: "prod",
				Cost:  uint64ptr(7),
			}, {
				Name:  "exempt",
				Value: false,
				Cost:  uint64ptr(9),
			}, {
				Name: "containers",
				Value: []any{
					map[string]any{
						"image":                    "prod.policy.example.com/google-samples/kubernetes-bootcamp:v1",
						"imagePullPolicy":          "IfNotPresent",
						"name":                     "kubernetes-bootcamp",
						"resources":                map[string]any{},
						"terminationMessagePath":   "/dev/termination-log",
						"terminationMessagePolicy": "File",
					},
				},
				Cost: uint64ptr(5),
			}, {
				Name: "containersToCheck",
				Value: []any{
					map[string]any{
						"image":                    "prod.policy.example.com/google-samples/kubernetes-bootcamp:v1",
						"imagePullPolicy":          "IfNotPresent",
						"name":                     "kubernetes-bootcamp",
						"resources":                map[string]any{},
						"terminationMessagePath":   "/dev/termination-log",
						"terminationMessagePolicy": "File",
					},
				},
				Cost: uint64ptr(18),
			}},
			Validations: []*k8s.EvalResult{{
				Result: true,
				Cost:   uint64ptr(11),
			}},
			Cost: uint64ptr(50),
		},
	}, {
		name:    "test an expression using request attributes",
		policy:  "request1 policy.yaml",
		orig:    "",
		updated: "request1 updated.yaml",
		request: "request1 request.yaml",
		expected: k8s.EvalResponse{
			Validations: []*k8s.EvalResult{{Result: true, Cost: uint64ptr(12)}},
			Cost:        uint64ptr(12),
		},
	}, {
		// Narrowing a check must not leak into the next chain, and an empty
		// resource must be an error rather than a silent denial.
		name:       "authorizer chains do not leak into one another",
		policy:     "authorizer4 policy.yaml",
		orig:       "",
		updated:    "authorizer4 updated.yaml",
		request:    "authorizer4 request.yaml",
		authorizer: "authorizer4 authorizer.yaml",
		expected: k8s.EvalResponse{
			Validations: []*k8s.EvalResult{
				// The narrowed chains cost two more than the un-narrowed one:
				// namespace() and name() are a call each.
				{Result: "object-scope", Cost: uint64ptr(350006)},
				{Result: "object-scope", Cost: uint64ptr(350006)},
				{Result: "cluster-scope", Cost: uint64ptr(350004)},
				// Reading authorizer.requestResource is 1 and the check 350000, so
				// the bare chain is 350002 and the narrowed one 350003.
				{Result: "kube-system-scope", Cost: uint64ptr(350003)},
				{Result: "namespace-scope", Cost: uint64ptr(350002)},
				{
					IsError: true,
					Error: strptr("unexpected error evaluating expression " +
						`authorizer.group("apps").resource("").check("update").allowed(): ` +
						"resource must not be empty"),
				},
				{
					IsError: true,
					Error: strptr("unexpected error evaluating expression " +
						`authorizer.group("apps").resource("deployments").check("").allowed(): ` +
						"must specify check"),
				},
				{
					IsError: true,
					Error: strptr("unexpected error evaluating expression " +
						`authorizer.path("/healthz").check("").allowed(): ` +
						"must specify check"),
				},
			},
			// The three erroring validations report no cost, so they add nothing.
			Cost: uint64ptr(1750021),
		},
	}, {
		// The Request tab names the resource and the namespace but no name, so
		// requestResource is the check on that namespace with no name.
		name:       "authorizer.requestResource takes the namespace from the request",
		policy:     "authorizer3 policy.yaml",
		orig:       "",
		updated:    "authorizer3 updated.yaml",
		request:    "authorizer3 request.yaml",
		authorizer: "authorizer3 authorizer.yaml",
		expected: k8s.EvalResponse{
			Validations: []*k8s.EvalResult{{Result: "namespace-scope", Cost: uint64ptr(350002)}},
			Cost:        uint64ptr(350002),
		},
	}, {
		// Each scoping call replaces what an earlier one in the same chain set. An
		// empty argument clears it, and an empty namespace is the cluster scope.
		name:       "authorizer chains scope by their last call",
		policy:     "authorizer5 policy.yaml",
		orig:       "",
		updated:    "authorizer5 updated.yaml",
		authorizer: "authorizer5 authorizer.yaml",
		expected: k8s.EvalResponse{
			// Every chain costs 350004 for reading authorizer, group(), resource(),
			// check() and the accessor, plus one per scoping call.
			Validations: []*k8s.EvalResult{
				{Result: "scale-subresource", Cost: uint64ptr(350006)},
				{Result: "cluster-scope", Cost: uint64ptr(350006)},
				{Result: "namespace-scope", Cost: uint64ptr(350007)},
				{Result: "cluster-scope", Cost: uint64ptr(350006)},
			},
			Cost: uint64ptr(1400025),
		},
	}, {
		// Every level of the Authorizer tab written as a key with no body under it:
		// a path, a group, a resource, a decision, a service account, and the group
		// authorizer.requestResource is built from. None of them has any checks, so
		// each one answers no opinion.
		name:       "authorizer entries with no checks answer no opinion",
		policy:     "authorizer6 policy.yaml",
		orig:       "",
		updated:    "authorizer6 updated.yaml",
		request:    "authorizer6 request.yaml",
		authorizer: "authorizer6 authorizer.yaml",
		expected: k8s.EvalResponse{
			Validations: []*k8s.EvalResult{
				{Result: false, Cost: uint64ptr(350003)},
				{Result: false, Cost: uint64ptr(350004)},
				{Result: false, Cost: uint64ptr(350004)},
				{Result: false, Cost: uint64ptr(350004)},
				{Result: false, Cost: uint64ptr(350005)},
				{Result: false, Cost: uint64ptr(350002)},
			},
			Cost: uint64ptr(2100022),
		},
	}, {
		// A request for a subresource checks the subresource's own entry, not the
		// entry for the resource holding it.
		name:       "authorizer.requestResource takes the subresource from the request",
		policy:     "authorizer7 policy.yaml",
		orig:       "",
		updated:    "authorizer7 updated.yaml",
		request:    "authorizer7 request.yaml",
		authorizer: "authorizer7 authorizer.yaml",
		expected: k8s.EvalResponse{
			Validations: []*k8s.EvalResult{{Result: "scale-in-default", Cost: uint64ptr(350002)}},
			Cost:        uint64ptr(350002),
		},
	}, {
		// The Request tab names the object and its namespace, so requestResource is
		// the check on that name in that namespace. The Request tab is the only
		// source; the object is not consulted.
		name:       "authorizer.requestResource takes the name and namespace from the request",
		policy:     "authorizer9 policy.yaml",
		orig:       "",
		updated:    "authorizer9 updated.yaml",
		request:    "authorizer9 request.yaml",
		authorizer: "authorizer9 authorizer.yaml",
		expected: k8s.EvalResponse{
			Validations: []*k8s.EvalResult{{Result: "nginx-in-default", Cost: uint64ptr(350002)}},
			Cost:        uint64ptr(350002),
		},
	}, {
		// A decision the fixture writes as a deny, and one it writes as an error,
		// read through all four of the accessors a policy can call on it.
		name:       "authorizer decisions that are not an allow",
		policy:     "authorizer8 policy.yaml",
		orig:       "",
		updated:    "authorizer8 updated.yaml",
		authorizer: "authorizer8 authorizer.yaml",
		expected: k8s.EvalResponse{
			// A resource chain costs 350004 and a path chain 350003: the check is
			// 350000, reading authorizer is 1, and each call around it -- the scoping
			// calls and the accessor -- is 1.
			Validations: []*k8s.EvalResult{
				{Result: false, Cost: uint64ptr(350004)},
				{Result: "denied-by-the-fixture", Cost: uint64ptr(350004)},
				{Result: false, Cost: uint64ptr(350004)},
				{Result: "", Cost: uint64ptr(350004)},
				{Result: true, Cost: uint64ptr(350004)},
				{Result: "the webhook authorizer is unavailable", Cost: uint64ptr(350004)},
				{Result: false, Cost: uint64ptr(350004)},
				{Result: "", Cost: uint64ptr(350004)},
				{Result: false, Cost: uint64ptr(350003)},
				{Result: "the /healthz path is for the kubelet", Cost: uint64ptr(350003)},
			},
			Cost: uint64ptr(3500038),
		},
	}, {
		name:       "test an expression using allowed authorizer checks",
		policy:     "authorizer1 policy.yaml",
		orig:       "",
		updated:    "authorizer1 updated.yaml",
		namespace:  "authorizer1 namespace.yaml",
		authorizer: "authorizer1 authorizer.yaml",
		expected: k8s.EvalResponse{
			ValidationVariables: []*k8s.EvalVariable{{
				Name:  "environment",
				Value: "prod",
				Cost:  uint64ptr(7),
			}, {
				Name:  "isProd",
				Value: true,
				Cost:  uint64ptr(2),
			}},
			Validations: []*k8s.EvalResult{{
				Result: true,
				Cost:   uint64ptr(350009),
			}},
			AuditAnnotations: []*k8s.EvalResult{{
				Name:    strptr("test-annotation"),
				Message: "Deployment is allowed in namespace default",
				Cost:    uint64ptr(4),
			}},
			Cost: uint64ptr(350022),
		},
	}, {
		name:       "test an expression using disallowed authorizer checks",
		policy:     "authorizer2 policy.yaml",
		orig:       "",
		updated:    "authorizer2 updated.yaml",
		namespace:  "authorizer2 namespace.yaml",
		authorizer: "authorizer2 authorizer.yaml",
		expected: k8s.EvalResponse{
			ValidationVariables: []*k8s.EvalVariable{{
				Name:  "environment",
				Value: "prod",
				Cost:  uint64ptr(7),
			}, {
				Name:  "isProd",
				Value: true,
				Cost:  uint64ptr(2),
			}},
			Validations: []*k8s.EvalResult{{
				Result: false,
				Cost:   uint64ptr(350009),
			}},
			Cost: uint64ptr(350018),
		},
	}, {
		name:    "test a broken expression within variables, expression should fail with no audit annotation",
		policy:  "broken1 policy.yaml",
		orig:    "",
		updated: "broken1 updated.yaml",
		expected: k8s.EvalResponse{
			ValidationVariables: []*k8s.EvalVariable{{
				Name:  "foo",
				Value: "default",
				Cost:  uint64ptr(6),
			}, {
				Name:    "containers",
				IsError: true,
				Error:   strptr("unexpected error evaluating expression containers: no such key: spc"),
			}},
			Validations: []*k8s.EvalResult{{
				IsError: true,
				Error:   strptr("unexpected error evaluating expression 'variables.foo == 'default' && variables.containers.all(c, c.image.startsWith(\"test\"))', caused by nested exception: 'no such key: spc'"),
			}},
			AuditAnnotations: []*k8s.EvalResult{{
				Name:    strptr("foo-label"),
				Message: "Label for foo is set to default",
				Cost:    uint64ptr(2),
			}},
			Cost: uint64ptr(8),
		},
	}, {
		name:    "test optional.none() dereference",
		policy:  "optional_none_dereference policy.yaml",
		orig:    "",
		updated: "optional_none_dereference updated.yaml",

		expected: k8s.EvalResponse{
			ValidationVariables: []*k8s.EvalVariable{{
				Name: "containers",
				Value: []any{
					map[string]any{
						"image":                    "gcr.io/google-samples/kubernetes-bootcamp:v1",
						"imagePullPolicy":          "IfNotPresent",
						"name":                     "kubernetes-bootcamp",
						"resources":                map[string]any{},
						"terminationMessagePath":   "/dev/termination-log",
						"terminationMessagePolicy": "File",
					},
				},
				Cost: uint64ptr(5),
			}, {
				Name:  "securityContexts",
				Value: []any{nil},
				Cost:  uint64ptr(15),
			}, {
				Name: "namedSecurityContexts",
				Value: []any{
					map[string]any{
						"kubernetes-bootcamp": nil,
					},
				},
				Cost: uint64ptr(47),
			}},
			Validations: []*k8s.EvalResult{{
				Result:  false,
				Message: "all containers must set runAsNonRoot to true",
				Cost:    uint64ptr(8),
			}, {
				Result:  false,
				Message: "all containers must set readOnlyRootFilesystem to true",
				Cost:    uint64ptr(8),
			}, {
				Result: true,
				Cost:   uint64ptr(8),
			}, {
				Result: true,
				Cost:   uint64ptr(8),
			}, {
				Result: true,
				Cost:   uint64ptr(8),
			}},
			Cost: uint64ptr(107),
		},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, orig, updated, namespace, request, authorizer, err := readValidationTestData(tt.policy, tt.orig, tt.updated, tt.namespace, tt.request, tt.authorizer)
			var results string
			if err == nil {
				results, err = k8s.EvalValidatingAdmissionPolicy(policy, orig, updated, namespace, request, authorizer)
			}
			if err != nil {
				if !tt.wantErr {
					t.Errorf("Eval() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				evalResponse := k8s.EvalResponse{}
				if err := json.Unmarshal([]byte(results), &evalResponse); err != nil {
					t.Errorf("Eval() error = %v", err)
				}
				if !reflect.DeepEqual(tt.expected, evalResponse) {
					expected, expErr := json.Marshal(tt.expected)
					response, respErr := json.Marshal(evalResponse)
					if expErr != nil || respErr != nil {
						t.Errorf("Error marshalling expected results or evaluated responses: %v, %v", expErr, respErr)
					} else {
						t.Errorf("Expected %s\n, received %s", expected, response)
					}
				}
			}
		})
	}
}

// TestValidationCELLibraries exercises the CEL libraries added to k8s/cel.go so
// they stay wired up. Each case is a validation expression that uses one
// library and must evaluate to true. It asserts availability, not cost, so it
// checks the result and the absence of an error and does not pin a cost.
func TestValidationCELLibraries(t *testing.T) {
	object := `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"x"}}`
	cases := []struct {
		lib  string
		expr string
	}{
		{"semver", `semver('1.2.3').minor() == 2`},
		{"ip", `isIP('10.0.0.1') && ip('10.0.0.1').family() == 4`},
		{"cidr", `isCIDR('10.0.0.0/8') && cidr('10.0.0.0/8').containsIP(ip('10.0.0.1'))`},
		{"format", `format.named('dns1123Label').hasValue()`},
		{"sets", `sets.contains([1, 2, 3], [2, 3])`},
		{"twoVarComprehensions", `[10, 20, 30].all(i, v, v >= 10)`},
		{"extLists", `[3, 1, 2].sort() == [1, 2, 3]`},
	}
	for _, tc := range cases {
		t.Run(tc.lib, func(t *testing.T) {
			policy := `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: lib-check
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
    - apiGroups: ["apps"]
      apiVersions: ["v1"]
      operations: ["CREATE"]
      resources: ["deployments"]
  validations:
    - expression: "` + tc.expr + `"
`
			out, err := k8s.EvalValidatingAdmissionPolicy([]byte(policy), nil, []byte(object), nil, nil, nil)
			if err != nil {
				t.Fatalf("Eval() error = %v", err)
			}
			var resp k8s.EvalResponse
			if err := json.Unmarshal([]byte(out), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if len(resp.Validations) != 1 {
				t.Fatalf("got %d validations, want 1: %s", len(resp.Validations), out)
			}
			v := resp.Validations[0]
			if v.IsError {
				msg := "<nil>"
				if v.Error != nil {
					msg = *v.Error
				}
				t.Fatalf("%s expression errored (library not registered?): %s", tc.lib, msg)
			}
			if v.Result != true {
				t.Errorf("%s expression = %v, want true", tc.lib, v.Result)
			}
		})
	}
}

// The wasm entry point hands every editor tab to the evaluator as a string, so an
// untouched tab arrives as an empty byte slice rather than as nil. The table above
// passes nil for an absent fixture, which is a shape the browser never produces --
// so the empty-slice shape needs its own case.
func TestEmptyTabsAsTheWasmEntryPointPassesThem(t *testing.T) {
	policy := []byte(`apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: empty-tabs
spec:
  validations:
  - expression: "object.spec.replicas <= 3"
`)
	object := []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: nginx\nspec:\n  replicas: 1\n")
	empty := []byte("")

	out, err := k8s.EvalValidatingAdmissionPolicy(policy, empty, object, empty, empty, empty)
	if err != nil {
		t.Fatalf("EvalValidatingAdmissionPolicy() with empty tabs: %v", err)
	}
	var response k8s.EvalResponse
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(response.Validations) != 1 || response.Validations[0].Result != true {
		t.Errorf("validations = %+v, want one true result", response.Validations)
	}

	// An empty Request tab names no resource for authorizer.requestResource to be a
	// check on. It is still bound, and answers no opinion, because a policy that
	// reads it should report that rather than fail to evaluate.
	authorizerPolicy := []byte(`apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: empty-tabs-authorizer
spec:
  validations:
  - expression: "authorizer.requestResource.check('update').allowed()"
`)
	out, err = k8s.EvalValidatingAdmissionPolicy(authorizerPolicy, empty, object, empty, empty, empty)
	if err != nil {
		t.Fatalf("EvalValidatingAdmissionPolicy() reading requestResource with empty tabs: %v", err)
	}
	response = k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(response.Validations) != 1 {
		t.Fatalf("validations = %+v, want exactly one", response.Validations)
	}
	if response.Validations[0].Result != false {
		t.Errorf("validations = %+v, want one false result", response.Validations)
	}
	if response.Validations[0].IsError {
		t.Errorf("validation errored: %v", *response.Validations[0].Error)
	}
}
