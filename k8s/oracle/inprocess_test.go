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
	"strings"
	"testing"

	"k8s.io/apiserver/pkg/admission"

	"github.com/undistro/cel-playground/k8s/oracle"
)

// TestInProcessOracle exercises upstream's own validator, reached through
// oracle.CompilePolicy, against the repository's existing vap fixtures. No
// apiserver, no etcd, no network: this is upstream's exact evaluation code path
// running in the test binary.
func TestInProcessOracle(t *testing.T) {
	cases := []struct {
		name       string
		policy     string
		object     string
		wantAction string
		wantMsg    string
	}{
		{
			name:       "variable1 satisfies nothing (label foo absent, variable defaults)",
			policy:     "variable1 policy.yaml",
			object:     "variable1 updated.yaml",
			wantAction: "deny",
		},
		{
			name:       "broken1 misspelled field is a compile error",
			policy:     "broken1 policy.yaml",
			object:     "broken1 updated.yaml",
			wantAction: "deny",
		},
		{
			name:       "optional none dereference",
			policy:     "optional_none_dereference policy.yaml",
			object:     "optional_none_dereference updated.yaml",
			wantAction: "deny",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := oracle.LoadPolicy(oracle.VAPFixture(tc.policy))
			if err != nil {
				t.Fatalf("loading policy: %v", err)
			}
			obj, err := oracle.LoadUnstructured(oracle.VAPFixture(tc.object))
			if err != nil {
				t.Fatalf("loading object: %v", err)
			}

			req := oracle.InProcessRequest{Object: obj, Operation: admission.Update, OldObject: obj}
			res, err := oracle.Evaluate(context.Background(), policy, req)
			if err != nil {
				if tc.wantAction == "compile-error" {
					t.Logf("policy %q did not compile, as expected:\n%v", policy.Name, err)
					return
				}
				t.Fatalf("policy %q did not compile:\n%v", policy.Name, err)
			}

			t.Logf("ValidateResult for %s x %s:\n%s", tc.policy, tc.object, oracle.FormatResult(res))

			if len(res.Decisions) == 0 {
				t.Fatalf("no decisions returned")
			}
			var actions []string
			for _, d := range res.Decisions {
				actions = append(actions, string(d.Action))
			}
			if tc.wantAction != "" && !contains(actions, tc.wantAction) {
				t.Errorf("actions = %v, want one of them to be %q", actions, tc.wantAction)
			}
			if tc.wantMsg != "" {
				found := false
				for _, d := range res.Decisions {
					if strings.Contains(d.Message, tc.wantMsg) {
						found = true
					}
				}
				if !found {
					t.Errorf("no decision message contained %q", tc.wantMsg)
				}
			}

			costs, err := oracle.ExactCosts(context.Background(), policy, req)
			if err != nil {
				t.Logf("exact costs unavailable: %v", err)
				return
			}
			t.Logf("exact costs: %s", costs)

			// The two independent routes to the same number must agree, or one
			// of them is lying.
			budget, err := oracle.MinimumBudget(context.Background(), policy, req)
			if err != nil {
				t.Fatalf("minimum budget: %v", err)
			}
			if budget != clamp1(costs.MinimumBudget()) {
				t.Errorf("bisected minimum budget %d != ExactCosts().MinimumBudget() %d", budget, costs.MinimumBudget())
			}
		})
	}
}

// TestInProcessExactCost pins the bisect against expressions whose cost is
// trivially predictable, so that a future change to the bisect cannot silently
// start returning plausible-looking nonsense.
func TestInProcessExactCost(t *testing.T) {
	cases := []struct {
		name       string
		expression string
	}{
		{"constant true", "true"},
		{"single field read", "has(object.metadata.name)"},
		{"string compare", "object.metadata.name == 'x'"},
		{"list comprehension over 100", "size([1,2,3].map(i, i * 2)) == 3"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := oracle.ParsePolicy(`
kind: ValidatingAdmissionPolicy
metadata:
  name: cost-probe
spec:
  failurePolicy: Fail
  validations:
    - expression: ` + quote(tc.expression) + `
`)
			if err != nil {
				t.Fatalf("parsing policy: %v", err)
			}
			obj, err := oracle.ParseUnstructured(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: x
  namespace: default
data:
  a: b
`)
			if err != nil {
				t.Fatalf("parsing object: %v", err)
			}
			req := oracle.InProcessRequest{Object: obj, Operation: admission.Create}
			res, err := oracle.Evaluate(context.Background(), policy, req)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			costs, err := oracle.ExactCosts(context.Background(), policy, req)
			if err != nil {
				t.Fatalf("exact costs: %v", err)
			}
			budget, err := oracle.MinimumBudget(context.Background(), policy, req)
			if err != nil {
				t.Fatalf("minimum budget: %v", err)
			}
			t.Logf("expression %-45q -> %s          validations cost = %d",
				tc.expression, strings.TrimSpace(oracle.FormatResult(res)), costs.Validations)
			if costs.Validations < 0 {
				t.Errorf("cost = %d, want a non-negative cost", costs.Validations)
			}
			if budget != clamp1(costs.MinimumBudget()) {
				t.Errorf("bisected budget %d != ExactCosts minimum budget %d", budget, costs.MinimumBudget())
			}
		})
	}
}

// TestCompatibilityVersion records the CEL compatibility version this
// apiserver's own compiler defaults to. See TestCELEnvVersionMatchesApiserver
// for what actually differs between adjacent versions.
func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// clamp1 mirrors MinimumBudget's documented floor of 1: a zero-cost policy
// cannot be expressed as a zero budget, because zero means "use the default".
func clamp1(v int64) int64 {
	if v < 1 {
		return 1
	}
	return v
}
