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
	"strings"
	"testing"

	"github.com/undistro/cel-playground/k8s"
)

func evalMutation(t *testing.T, policy, object, request, rbac string) k8s.EvalResponse {
	t.Helper()
	out, err := k8s.EvalMutatingAdmissionPolicy(
		readMapFile(t, policy), nil, readMapFile(t, object), nil,
		readMapFile(t, request), readMapFile(t, rbac))
	if err != nil {
		t.Fatalf("EvalMutatingAdmissionPolicy() error: %v", err)
	}
	response := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	return response
}

// A JSON Patch can grow a document without spending CEL cost: `copy` duplicates
// a subtree for a handful of cost units whatever its size, so twelve of them
// turn a 400-byte object into megabytes at a cost of 490 out of ten million.
// The cost budget does not bound output size, and both of these bounds exist
// because of a reproduced attack of exactly that shape.
//
// The object is a custom resource on purpose. A built-in would be read back
// against its schema and refused for the undeclared fields the copies create,
// which is a different bound entirely and would hide these two.
func TestMutationBoundsTheObjectItProduces(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		want   string
	}{{
		// Bounded by the playground: nothing upstream limits what a policy
		// accumulates across mutations, and an object this size is one no
		// cluster would have carried in a request body.
		name:   "an object grown past what a cluster would store is not applied",
		policy: "copy grows the object policy.yaml",
		want:   "past the 1048576 a cluster accepts in a request body",
	}, {
		// Bounded by the patch library, armed from the apiserver's own
		// JSONPatchMaxCopyBytes. Without the init() that arms it the default is
		// unlimited, because the playground never builds a GenericAPIServer.
		name:   "a patch that copies past the accumulated-copy limit is refused",
		policy: "copy exceeds the patch limit policy.yaml",
		want:   "exceeding the limit 3145728",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := k8s.EvalMutatingAdmissionPolicy(
				readMapFile(t, tt.policy), nil, readMapFile(t, "bomb object.yaml"), nil, nil, nil)
			if err != nil {
				t.Fatalf("EvalMutatingAdmissionPolicy() error: %v", err)
			}
			// The response is what crosses into the browser, so its size is the
			// thing being bounded. A megabyte here is the attack succeeding.
			if len(out) > 4096 {
				t.Errorf("the response is %d bytes; the mutated object was not withheld", len(out))
			}
			response := k8s.EvalResponse{}
			if err := json.Unmarshal([]byte(out), &response); err != nil {
				t.Fatalf("json.Unmarshal() error: %v", err)
			}
			if len(response.Mutations) != 1 {
				t.Fatalf("got %d mutations, want 1", len(response.Mutations))
			}
			mutation := response.Mutations[0]
			if !mutation.IsError || mutation.Error == nil {
				t.Fatalf("the mutation was applied, want it refused")
			}
			if !strings.Contains(*mutation.Error, tt.want) {
				t.Errorf("error = %q, want it to mention %q", *mutation.Error, tt.want)
			}
			if mutation.MutatedObject != "" {
				t.Errorf("the refused object was reported anyway (%d bytes)", len(mutation.MutatedObject))
			}
			if response.FinalObject != "" {
				t.Errorf("the refused object became the final object (%d bytes)", len(response.FinalObject))
			}
		})
	}
}

// notSimulated is what stops a policy the playground only half-runs from
// reporting a confident result. Each line is a field the mode parses and does
// not act on, and each is reported whatever the matchConditions did -- a policy
// gated off by its own matchConditions is exactly when the reader has least
// else to go on.
func TestMutationReportsWhatItDoesNotSimulate(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		want   []string
		absent []string
	}{{
		name:   "matchConstraints and defaulting",
		policy: "applyconfig label policy.yaml",
		want:   []string{"matchConstraints:", "API defaults:"},
		absent: []string{"paramKind:", "reinvocationPolicy:"},
	}, {
		name:   "paramKind, even when the policy never fires",
		policy: "gated paramkind policy.yaml",
		want:   []string{"matchConstraints:", "paramKind:", "API defaults:"},
	}, {
		name:   "a policy with no matchConstraints does not claim to ignore them",
		policy: "crd jsonpatch policy.yaml",
		want:   []string{"API defaults:"},
		absent: []string{"matchConstraints:", "paramKind:"},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := evalMutation(t, tt.policy, "object.yaml", "", "")
			for _, want := range tt.want {
				if !strings.Contains(response.NotSimulated, want) {
					t.Errorf("notSimulated does not mention %q:\n%s", want, response.NotSimulated)
				}
			}
			for _, absent := range tt.absent {
				if strings.Contains(response.NotSimulated, absent) {
					t.Errorf("notSimulated mentions %q, which this policy does not use:\n%s", absent, response.NotSimulated)
				}
			}
		})
	}
}

// reinvocationPolicy: IfNeeded asks the apiserver for another pass once some
// other plugin has mutated the object. There is no other plugin here, so each
// mutation runs once and the panel has to say so.
func TestMutationReportsReinvocation(t *testing.T) {
	policy := strings.Replace(string(readMapFile(t, "applyconfig label policy.yaml")),
		"reinvocationPolicy: Never", "reinvocationPolicy: IfNeeded", 1)
	out, err := k8s.EvalMutatingAdmissionPolicy([]byte(policy), nil, readMapFile(t, "object.yaml"), nil, nil, nil)
	if err != nil {
		t.Fatalf("EvalMutatingAdmissionPolicy() error: %v", err)
	}
	response := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if !strings.Contains(response.NotSimulated, "reinvocationPolicy:") {
		t.Errorf("notSimulated does not mention reinvocationPolicy:\n%s", response.NotSimulated)
	}
}

// A mutation names its patch type and carries a body matching it. A policy that
// disagrees with itself is refused by the registry, so it never reaches a
// cluster and the mutation has nothing to run.
func TestMutationRejectsAMalformedPatchType(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		want   string
		reject bool
	}{{
		name: "ApplyConfiguration with no applyConfiguration",
		body: "  - patchType: ApplyConfiguration\n",
		want: "patchType is ApplyConfiguration, so applyConfiguration.expression must be set",
	}, {
		name: "JSONPatch with no jsonPatch",
		body: "  - patchType: JSONPatch\n",
		want: "patchType is JSONPatch, so jsonPatch.expression must be set",
	}, {
		name: "no patchType at all",
		body: "  - jsonPatch:\n      expression: \"[]\"\n",
		want: "patchType is not set; expected ApplyConfiguration or JSONPatch",
	}, {
		name: "a patch type that does not exist",
		body: "  - patchType: StrategicMerge\n    jsonPatch:\n      expression: \"[]\"\n",
		want: `unsupported patchType "StrategicMerge"`,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := "apiVersion: admissionregistration.k8s.io/v1\nkind: MutatingAdmissionPolicy\nmetadata:\n  name: malformed\nspec:\n  failurePolicy: Fail\n  reinvocationPolicy: Never\n  mutations:\n" + tt.body
			out, err := k8s.EvalMutatingAdmissionPolicy([]byte(policy), nil, readMapFile(t, "object.yaml"), nil, nil, nil)
			if err != nil {
				t.Fatalf("EvalMutatingAdmissionPolicy() error: %v", err)
			}
			response := k8s.EvalResponse{}
			if err := json.Unmarshal([]byte(out), &response); err != nil {
				t.Fatalf("json.Unmarshal() error: %v", err)
			}
			if len(response.Mutations) != 1 {
				t.Fatalf("got %d mutations, want 1: %s", len(response.Mutations), out)
			}
			if !response.Mutations[0].IsError {
				t.Fatalf("the mutation ran, want it refused")
			}
			if got := *response.Mutations[0].Error; !strings.Contains(got, tt.want) {
				t.Errorf("error = %q, want it to mention %q", got, tt.want)
			}
		})
	}
}

// Each mutation is patched on its own with a whole cost budget, the way the
// dispatcher hands celconfig.RuntimeCELCostBudget to every Patch call. Two
// mutations that each stay inside it do not add up to an overrun.
func TestMutationBudgetsArePerMutation(t *testing.T) {
	// One authorizer check is ~350,000 units. Six of them in one expression run
	// past two million but nowhere near ten, so a shared budget and a per
	// mutation one are told apart by the total rather than by either chain.
	check := "string(authorizer.group('apps').resource('deployments').check('update').allowed())"
	mutation := "  - patchType: ApplyConfiguration\n    applyConfiguration:\n      expression: >\n        Object{metadata: Object.metadata{annotations: {\"a\": " + check + "}}}\n"
	policy := "apiVersion: admissionregistration.k8s.io/v1\nkind: MutatingAdmissionPolicy\nmetadata:\n  name: budgets\nspec:\n  failurePolicy: Fail\n  reinvocationPolicy: Never\n  mutations:\n" + mutation + mutation

	out, err := k8s.EvalMutatingAdmissionPolicy([]byte(policy), nil, readMapFile(t, "object.yaml"), nil, nil, nil)
	if err != nil {
		t.Fatalf("EvalMutatingAdmissionPolicy() error: %v", err)
	}
	response := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if len(response.Mutations) != 2 {
		t.Fatalf("got %d mutations, want 2", len(response.Mutations))
	}
	for i, m := range response.Mutations {
		if m.IsError {
			t.Fatalf("mutations[%d] failed: %s", i, *m.Error)
		}
		if m.Cost == nil || *m.Cost == 0 {
			t.Fatalf("mutations[%d] reported no cost", i)
		}
	}
	if len(response.ExceededBudgets) != 0 {
		t.Errorf("a budget was reported as exceeded: %v", *response.ExceededBudgets[0].Error)
	}
}
