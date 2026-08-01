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

package k8s_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/undistro/cel-playground/k8s"
)

func mapTestfile(file string) string {
	return testfile("map/" + file)
}

func readMapFile(t *testing.T, file string) []byte {
	t.Helper()
	if file == "" {
		return nil
	}
	data, err := testdata.ReadFile(mapTestfile(file))
	if err != nil {
		t.Fatalf("reading %s: %v", file, err)
	}
	return data
}

type mutationCase struct {
	name      string
	policy    string
	object    string
	oldObject string
	namespace string
	request   string
	rbac      string
	// mutated names a fixture holding the object the policy is expected to
	// leave behind, or is empty when the object should come back untouched.
	mutated string
	// expected is compared field by field, with the object bodies removed: the
	// mutated object is held to `mutated` instead, so that a change to it shows
	// up as a diff between two YAML files rather than inside a Go string.
	expected k8s.EvalResponse
	decision string
	warnings []string
	wantErr  bool
}

func TestMutationEval(t *testing.T) {
	tests := []mutationCase{{
		name:    "an ApplyConfiguration adds a label and keeps the ones already there",
		policy:  "applyconfig label policy.yaml",
		object:  "object.yaml",
		mutated: "applyconfig label mutated.yaml",
		expected: k8s.EvalResponse{
			Mutations: []*k8s.EvalMutationResult{{PatchType: "ApplyConfiguration", Cost: uint64ptr(80)}},
			Cost:      uint64ptr(80),
		},
		decision: "admitted: every mutation ran, and the object is mutated",
	}, {
		// The mutation adds one entry to spec.template.spec.initContainers,
		// which is x-kubernetes-list-type=map keyed by name. Merging by that key
		// is the whole reason the binary carries a merge schema: without one the
		// list is atomic and "setup" disappears.
		name:    "an ApplyConfiguration merges a keyed list by key",
		policy:  "sidecar policy.yaml",
		object:  "sidecar object.yaml",
		mutated: "sidecar mutated.yaml",
		expected: k8s.EvalResponse{
			Mutations: []*k8s.EvalMutationResult{{PatchType: "ApplyConfiguration", Cost: uint64ptr(210)}},
			Cost:      uint64ptr(210),
		},
		decision: "admitted: every mutation ran, and the object is mutated",
	}, {
		name:    "a mutation reads a variable, and the variable is charged to it",
		policy:  "variables policy.yaml",
		object:  "object.yaml",
		mutated: "variables mutated.yaml",
		expected: k8s.EvalResponse{
			MutationVariables: []*k8s.EvalVariable{{Name: "mutations[0].appName", Value: "nginx", Cost: uint64ptr(7)}},
			Mutations:         []*k8s.EvalMutationResult{{PatchType: "ApplyConfiguration", Cost: uint64ptr(112)}},
			Cost:              uint64ptr(119),
		},
		decision: "admitted: every mutation ran, and the object is mutated",
	}, {
		// The second mutation reads a label the first one wrote, so the object
		// really is threaded from one to the next rather than both running
		// against the input.
		name:    "each mutation runs against what the one before it produced",
		policy:  "chained policy.yaml",
		object:  "object.yaml",
		mutated: "chained mutated.yaml",
		expected: k8s.EvalResponse{
			Mutations: []*k8s.EvalMutationResult{
				{PatchType: "ApplyConfiguration", Cost: uint64ptr(80)},
				{PatchType: "ApplyConfiguration", Cost: uint64ptr(114)},
			},
			Cost: uint64ptr(194),
		},
		decision: "admitted: every mutation ran, and the object is mutated",
	}, {
		name:    "a JSONPatch adds and replaces",
		policy:  "jsonpatch ops policy.yaml",
		object:  "object.yaml",
		mutated: "jsonpatch ops mutated.yaml",
		expected: k8s.EvalResponse{
			Mutations: []*k8s.EvalMutationResult{{PatchType: "JSONPatch", Cost: uint64ptr(90)}},
			Cost:      uint64ptr(90),
		},
		decision: "admitted: every mutation ran, and the object is mutated",
	}, {
		name:    "jsonpatch.escapeKey escapes a slash in a label key",
		policy:  "jsonpatch escapekey policy.yaml",
		object:  "object.yaml",
		mutated: "jsonpatch escapekey mutated.yaml",
		expected: k8s.EvalResponse{
			Mutations: []*k8s.EvalMutationResult{{PatchType: "JSONPatch", Cost: uint64ptr(56)}},
			Cost:      uint64ptr(56),
		},
		decision: "admitted: every mutation ran, and the object is mutated",
	}, {
		// An ApplyConfiguration merges, and merging needs the schema of the
		// target type. A cluster reads a custom resource's from its CRD, and
		// merges by key or refuses the patch as atomic depending on what it
		// says; with neither in hand there is no answer to give.
		name:   "an ApplyConfiguration on a custom resource is refused, not guessed",
		policy: "crd policy.yaml",
		object: "crd object.yaml",
		expected: k8s.EvalResponse{
			Mutations: []*k8s.EvalMutationResult{{
				PatchType: "ApplyConfiguration",
				IsError:   true,
				Error:     strptr("there is no merge schema for example.com/v1 here, so what an ApplyConfiguration does to it cannot be answered: a cluster reads the schema from the CustomResourceDefinition, and merges by key or refuses the patch as atomic depending on what it says. The playground carries the schemas of the built-in Kubernetes APIs only; a JSONPatch needs none and still works"),
			}},
			Cost: uint64ptr(0),
		},
		decision: "rejected: mutations[0] failed and failurePolicy is Fail, so the request is denied and nothing is applied",
	}, {
		// A JSONPatch does not merge, so it needs no schema and is not warned
		// about on a custom resource.
		name:    "a JSONPatch on a custom resource needs no schema",
		policy:  "crd jsonpatch policy.yaml",
		object:  "crd object.yaml",
		mutated: "crd jsonpatch mutated.yaml",
		expected: k8s.EvalResponse{
			Mutations: []*k8s.EvalMutationResult{{PatchType: "JSONPatch", Cost: uint64ptr(50)}},
			Cost:      uint64ptr(50),
		},
		decision: "admitted: every mutation ran, and the object is mutated",
	}, {
		name:   "an expression of the wrong type does not compile, and costs nothing",
		policy: "broken policy.yaml",
		object: "object.yaml",
		expected: k8s.EvalResponse{
			Mutations: []*k8s.EvalMutationResult{{
				PatchType: "ApplyConfiguration",
				IsError:   true,
				Error:     strptr("must evaluate to Object but got int"),
			}},
			Cost: uint64ptr(0),
		},
		decision: "rejected: mutations[0] failed and failurePolicy is Fail, so the request is denied and nothing is applied",
	}, {
		// A matchCondition that errors stops the mutations under either
		// failurePolicy, so the playground can never show a mutated object a
		// cluster would not have produced.
		name:   "an erroring matchCondition runs no mutation",
		policy: "erroring matchcondition policy.yaml",
		object: "object.yaml",
		expected: k8s.EvalResponse{
			MatchConditions: []*k8s.EvalResult{{
				Name:    strptr("broken"),
				Cost:    uint64ptr(4),
				IsError: true,
				Error:   strptr("unexpected error evaluating expression object.spec.thisFieldDoesNotExist == 1: no such key: thisFieldDoesNotExist"),
			}},
			Cost: uint64ptr(4),
		},
		decision: "rejected: matchCondition \"broken\" failed and failurePolicy is Fail",
	}, {
		name:   "a false matchCondition runs no mutation",
		policy: "matchconditions false policy.yaml",
		object: "object.yaml",
		expected: k8s.EvalResponse{
			MatchConditions: []*k8s.EvalResult{{Name: strptr("is-production"), Result: false, Cost: uint64ptr(5)}},
			Cost:            uint64ptr(5),
		},
		decision: "admitted: matchCondition \"is-production\" is false, so the policy does not apply to this request",
	}, {
		name:   "a policy gated off by its own matchConditions still reports what is not simulated",
		policy: "gated paramkind policy.yaml",
		object: "object.yaml",
		expected: k8s.EvalResponse{
			MatchConditions: []*k8s.EvalResult{{Name: strptr("never"), Result: false, Cost: uint64ptr(0)}},
			Cost:            uint64ptr(0),
		},
		decision: "admitted: matchCondition \"never\" is false, so the policy does not apply to this request",
	}, {
		// YAML 1.1 turns bare on/yes/off into booleans, and `on` and `yes` both
		// become the key `true`, so one annotation is dropped -- exactly what a
		// cluster does with the same document. The mutation must not disturb
		// what survived.
		name:    "a mutation preserves the YAML 1.1 keys the object was decoded with",
		policy:  "yaml keys policy.yaml",
		object:  "yaml keys object.yaml",
		mutated: "yaml keys mutated.yaml",
		expected: k8s.EvalResponse{
			Mutations: []*k8s.EvalMutationResult{{PatchType: "ApplyConfiguration", Cost: uint64ptr(80)}},
			Cost:      uint64ptr(80),
		},
		decision: "admitted: every mutation ran, and the object is mutated",
	}, {
		// A cluster decodes a patched built-in strictly. The playground keeps
		// everything unstructured, so it reads the result back through the same
		// schema to reach the same answer.
		name:   "a JSONPatch that writes a string into an integer field is refused",
		policy: "quoted number policy.yaml",
		object: "object.yaml",
		expected: k8s.EvalResponse{
			Mutations: []*k8s.EvalMutationResult{{
				PatchType: "JSONPatch",
				Cost:      uint64ptr(50),
				IsError:   true,
				Error:     strptr("a cluster reads the patched object back against the Deployment schema and would refuse it: .spec.replicas: expected numeric (int or float), got string"),
			}},
			Cost: uint64ptr(50),
		},
		decision: "rejected: mutations[0] produced an object the apiserver cannot decode, which fails the request whatever failurePolicy says",
	}, {
		// Object{} has no compile-time field checking, so a misspelled field
		// reaches the merge. The schema is what catches it, as on a cluster.
		name:   "an ApplyConfiguration naming a field the schema does not declare is refused",
		policy: "patch typo policy.yaml",
		object: "object.yaml",
		expected: k8s.EvalResponse{
			Mutations: []*k8s.EvalMutationResult{{
				PatchType: "ApplyConfiguration",
				Cost:      uint64ptr(80),
				IsError:   true,
				Error:     strptr("error applying patch: failed to convert patch object to typed object: .spec.replicaz: field not declared in schema"),
			}},
			Cost: uint64ptr(80),
		},
		decision: "rejected: mutations[0] failed and failurePolicy is Fail, so the request is denied and nothing is applied",
	}, {
		// The dispatcher records a failed mutation and moves on to the next one,
		// which runs against the object as the failure left it -- unmutated.
		name:    "a failed mutation does not stop the ones after it",
		policy:  "chained typo policy.yaml",
		object:  "object.yaml",
		mutated: "chained typo mutated.yaml",
		expected: k8s.EvalResponse{
			Mutations: []*k8s.EvalMutationResult{{
				PatchType: "JSONPatch",
				Cost:      uint64ptr(50),
				IsError:   true,
				Error:     strptr("a cluster reads the patched object back against the Deployment schema and would refuse it: .spec.replicaz: field not declared in schema"),
			}, {
				PatchType: "ApplyConfiguration",
				Cost:      uint64ptr(80),
			}},
			Cost: uint64ptr(130),
		},
		decision: "rejected: mutations[0] produced an object the apiserver cannot decode, which fails the request whatever failurePolicy says",
	}, {
		name:    "a v1alpha1 policy evaluates as its v1 self",
		policy:  "v1alpha1 policy.yaml",
		object:  "object.yaml",
		mutated: "variables mutated.yaml",
		expected: k8s.EvalResponse{
			MutationVariables: []*k8s.EvalVariable{{Name: "mutations[0].appName", Value: "nginx", Cost: uint64ptr(7)}},
			Mutations:         []*k8s.EvalMutationResult{{PatchType: "ApplyConfiguration", Cost: uint64ptr(112)}},
			Cost:              uint64ptr(119),
		},
		decision: "admitted: every mutation ran, and the object is mutated",
	}, {
		name:    "a v1beta1 policy evaluates as its v1 self",
		policy:  "v1beta1 policy.yaml",
		object:  "object.yaml",
		mutated: "applyconfig label mutated.yaml",
		expected: k8s.EvalResponse{
			Mutations: []*k8s.EvalMutationResult{{PatchType: "ApplyConfiguration", Cost: uint64ptr(80)}},
			Cost:      uint64ptr(80),
		},
		decision: "admitted: every mutation ran, and the object is mutated",
	}, {
		// request, oldObject and the RBAC tab all read inside one mutation.
		name:      "a mutation reads the request, the old object and the authorizer",
		policy:    "context policy.yaml",
		object:    "object.yaml",
		oldObject: "context oldobject.yaml",
		request:   "context request.yaml",
		rbac:      "context rbac.yaml",
		mutated:   "context mutated.yaml",
		expected: k8s.EvalResponse{
			Mutations: []*k8s.EvalMutationResult{{PatchType: "ApplyConfiguration", Cost: uint64ptr(350122)}},
			Cost:      uint64ptr(350122),
		},
		decision: "admitted: every mutation ran, and the object is mutated",
	}, {
		// authorizer.serviceAccount swaps the user the checks are made as, and
		// Kubernetes' own RBAC authorizer resolves it through the service
		// account's groups.
		name:    "authorizer.serviceAccount asks about a different subject",
		policy:  "serviceaccount policy.yaml",
		object:  "object.yaml",
		request: "serviceaccount request.yaml",
		rbac:    "serviceaccount rbac.yaml",
		mutated: "serviceaccount mutated.yaml",
		expected: k8s.EvalResponse{
			Mutations: []*k8s.EvalMutationResult{{PatchType: "ApplyConfiguration", Cost: uint64ptr(700121)}},
			Cost:      uint64ptr(700121),
		},
		decision: "admitted: every mutation ran, and the object is mutated",
	}, {
		// The dispatcher skips a patcher when there is no object -- a DELETE
		// carries none -- and the request goes through, so this is not a
		// failure. It is still nearly always a blank Object tab, so the row
		// says what to do about it.
		name:   "a request with no object mutates nothing and is admitted",
		policy: "applyconfig label policy.yaml",
		expected: k8s.EvalResponse{
			Mutations: []*k8s.EvalMutationResult{{
				PatchType: "ApplyConfiguration",
				Message:   "a mutation needs something to mutate: paste the object the policy acts on into the Object tab",
			}},
			Cost: uint64ptr(0),
		},
		decision: "admitted: the request carries no object, so no mutation ran",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := k8s.EvalMutatingAdmissionPolicy(
				readMapFile(t, tt.policy),
				readMapFile(t, tt.oldObject),
				readMapFile(t, tt.object),
				readMapFile(t, tt.namespace),
				readMapFile(t, tt.request),
				readMapFile(t, tt.rbac),
			)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Eval() succeeded, want an error: %s", out)
				}
				return
			}
			if err != nil {
				t.Fatalf("Eval() error = %v", err)
			}

			response := k8s.EvalResponse{}
			if err := json.Unmarshal([]byte(out), &response); err != nil {
				t.Fatalf("Eval() produced undecodable JSON: %v", err)
			}

			assertDecision(t, response, tt.decision)
			assertWarnings(t, response, tt.warnings)
			assertMutatedObject(t, response, readMapFile(t, tt.mutated))

			// notSimulated is a property of the policy document rather than of
			// the run, and has a table of its own.
			response.Decision, response.Warnings, response.NotSimulated = nil, nil, ""
			response.Diff, response.FinalObject = "", ""
			for _, mutation := range response.Mutations {
				mutation.MutatedObject = ""
			}
			if !reflect.DeepEqual(tt.expected, response) {
				expected, _ := json.Marshal(tt.expected)
				got, _ := json.Marshal(response)
				t.Errorf("expected %s\n, received %s", expected, got)
			}
		})
	}
}

// A ValidatingAdmissionPolicy decodes perfectly well as a document and carries
// nothing this mode looks at, so without a kind check the panel would come back
// empty and say nothing about why.
func TestMutationEvalRejectsOtherKinds(t *testing.T) {
	for _, policy := range []string{"vap/policy1.yaml", "webhook/authorizer4.yaml"} {
		t.Run(policy, func(t *testing.T) {
			data, err := testdata.ReadFile(testfile(policy))
			if err != nil {
				t.Skipf("no fixture %s: %v", policy, err)
			}
			out, err := k8s.EvalMutatingAdmissionPolicy(data, nil, readMapFile(t, "object.yaml"), nil, nil, nil)
			if err == nil {
				t.Fatalf("Eval() accepted %s: %s", policy, out)
			}
			if !strings.Contains(err.Error(), "MutatingAdmissionPolicy") {
				t.Errorf("error %q does not say what this mode evaluates", err)
			}
		})
	}
}

func assertDecision(t *testing.T, response k8s.EvalResponse, want string) {
	t.Helper()
	if len(response.Decision) != 1 {
		t.Fatalf("got %d decisions, want 1", len(response.Decision))
	}
	if got, _ := response.Decision[0].Message.(string); got != want {
		t.Errorf("decision = %q, want %q", got, want)
	}
}

func assertWarnings(t *testing.T, response k8s.EvalResponse, want []string) {
	t.Helper()
	if len(response.Warnings) != len(want) {
		t.Fatalf("got %d warnings, want %d: %q", len(response.Warnings), len(want), response.Warnings)
	}
	for i, prefix := range want {
		if !strings.HasPrefix(response.Warnings[i], prefix) {
			t.Errorf("warnings[%d] = %q, want it to start with %q", i, response.Warnings[i], prefix)
		}
	}
}

// assertMutatedObject holds the object the policy left behind to a fixture. The
// last mutation's own output has to equal it: the final object is that object
// and not a re-serialization of anything else.
func assertMutatedObject(t *testing.T, response k8s.EvalResponse, want []byte) {
	t.Helper()
	if len(want) == 0 {
		if response.FinalObject != "" {
			t.Errorf("the object was mutated and no fixture says what to:\n%s", response.FinalObject)
		}
		if response.Diff != "" {
			t.Errorf("a diff was reported for an unmutated object:\n%s", response.Diff)
		}
		return
	}
	if response.FinalObject != string(want) {
		t.Errorf("final object:\n%s\nwant:\n%s", response.FinalObject, want)
	}
	if response.Diff == "" {
		t.Errorf("the object changed and no diff was reported")
	}
	var last string
	for _, mutation := range response.Mutations {
		if mutation.MutatedObject != "" {
			last = mutation.MutatedObject
		}
	}
	if last != response.FinalObject {
		t.Errorf("the final object is not what the last applied mutation produced:\n%s", last)
	}
}
