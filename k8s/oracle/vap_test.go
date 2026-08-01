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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/undistro/cel-playground/k8s/oracle"
)

// sanitize strips the server-owned metadata the repo's fixtures carry (they
// were captured off a live cluster), which the registry rejects on CREATE
// before admission ever runs.
func sanitize(obj *unstructured.Unstructured) *unstructured.Unstructured {
	out := obj.DeepCopy()
	out.SetResourceVersion("")
	out.SetUID("")
	out.SetGeneration(0)
	out.SetCreationTimestamp(metaV1Zero())
	out.SetManagedFields(nil)
	unstructured.RemoveNestedField(out.Object, "status")
	unstructured.RemoveNestedField(out.Object, "metadata", "creationTimestamp")
	if out.GetNamespace() == "" {
		out.SetNamespace("default")
	}
	return out
}

// TestVAPRealAdmission drives a table of (policy fixture, object fixture) pairs
// through a real kube-apiserver and records the decision, message and reason
// the cluster actually produces.
func TestVAPRealAdmission(t *testing.T) {
	o := cluster(t)
	ctx := context.Background()

	cases := []struct {
		name        string
		policy      string
		object      string
		wantAllowed bool
		wantMessage string // substring
	}{
		{
			name:        "variable read defaults, validation fails",
			policy:      "variable1 policy.yaml",
			object:      "variable1 updated.yaml",
			wantAllowed: false,
			wantMessage: "failed expression: variables.foo == 'bar'",
		},
		{
			name:        "variable read matches, validation passes",
			policy:      "variable2 policy.yaml",
			object:      "variable2 updated.yaml",
			wantAllowed: true,
		},
		{
			name:        "misspelled field surfaces as a runtime error under failurePolicy Fail",
			policy:      "broken1 policy.yaml",
			object:      "broken1 updated.yaml",
			wantAllowed: false,
			wantMessage: "no such key: spc",
		},
		{
			name:        "optional none dereference",
			policy:      "optional_none_dereference policy.yaml",
			object:      "optional_none_dereference updated.yaml",
			wantAllowed: false,
			wantMessage: "runAsNonRoot",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := oracle.LoadPolicy(oracle.VAPFixture(tc.policy))
			if err != nil {
				t.Fatalf("loading policy: %v", err)
			}
			// Unique name per case so a leaked policy from a previous case
			// cannot silently satisfy this one.
			policy.Name = "oracle-vap-" + sanitizeName(tc.name)
			policy.ResourceVersion = ""

			obj, err := oracle.LoadUnstructured(oracle.VAPFixture(tc.object))
			if err != nil {
				t.Fatalf("loading object: %v", err)
			}
			obj = sanitize(obj)

			cleanup, err := o.CreatePolicyAndBinding(ctx, policy, nil)
			if err != nil {
				t.Fatalf("installing policy: %v", err)
			}
			defer cleanup()

			if err := o.WaitPoliciesActive(ctx); err != nil {
				t.Fatalf("waiting for policy to become active: %v", err)
			}

			decision, err := o.DryRunCreate(ctx, obj)
			if err != nil {
				t.Fatalf("issuing dry-run create: %v", err)
			}
			t.Logf("real apiserver decision for %s x %s:\n  %s", tc.policy, tc.object, decision)

			if decision.Allowed != tc.wantAllowed {
				t.Errorf("allowed = %v, want %v", decision.Allowed, tc.wantAllowed)
			}
			if tc.wantMessage != "" && !strings.Contains(decision.Message, tc.wantMessage) {
				t.Errorf("message %q does not contain %q", decision.Message, tc.wantMessage)
			}
		})
	}
}

// TestVAPMatchesInProcessOracle is the differential test proper: for the same
// policy and object, the in-process reproduction of upstream's compilePolicy
// must reach the same verdict as the real apiserver. If these two ever
// disagree, the in-process oracle has drifted from upstream and every result it
// reports is suspect.
func TestVAPMatchesInProcessOracle(t *testing.T) {
	o := cluster(t)
	ctx := context.Background()

	fixtures := []struct{ policy, object string }{
		{"variable1 policy.yaml", "variable1 updated.yaml"},
		{"variable2 policy.yaml", "variable2 updated.yaml"},
		{"variable3 policy.yaml", "variable3 updated.yaml"},
		{"variable4 policy.yaml", "variable4 updated.yaml"},
		{"optional_none_dereference policy.yaml", "optional_none_dereference updated.yaml"},
	}

	for _, f := range fixtures {
		t.Run(f.policy, func(t *testing.T) {
			policy, err := oracle.LoadPolicy(oracle.VAPFixture(f.policy))
			if err != nil {
				t.Fatalf("loading policy: %v", err)
			}
			obj, err := oracle.LoadUnstructured(oracle.VAPFixture(f.object))
			if err != nil {
				t.Fatalf("loading object: %v", err)
			}
			obj = sanitize(obj)

			// In-process verdict.
			res, err := oracle.Evaluate(ctx, policy, oracle.InProcessRequest{Object: obj})
			if err != nil {
				t.Fatalf("in-process evaluate: %v", err)
			}
			inProcessDenied := false
			inProcessErrored := false
			for _, d := range res.Decisions {
				if string(d.Action) == "deny" {
					inProcessDenied = true
				}
				if string(d.Evaluation) == "error" {
					inProcessErrored = true
				}
			}

			// Cluster verdict.
			policy.Name = "oracle-diff-" + sanitizeName(f.policy)
			cleanup, err := o.CreatePolicyAndBinding(ctx, policy, nil)
			if err != nil {
				// The apiserver refused to STORE the policy. That is registry
				// validation, a gate ahead of admission that the playground
				// does not model at all -- so there is no admission decision to
				// compare against, and the finding is the rejection itself.
				t.Logf("REGISTRY REJECTION: a real apiserver will not accept this fixture at all:\n%v", err)
				t.Logf("  in-process runtime evaluation reached a decision anyway (errored=%v, denied=%v)",
					inProcessErrored, inProcessDenied)
				t.Logf("  in-process: %s", strings.TrimSpace(oracle.FormatResult(res)))
				if !inProcessErrored && !inProcessDenied {
					t.Errorf("the cluster rejects this policy outright but the runtime evaluator admits it silently")
				}
				return
			}
			defer cleanup()
			if err := o.WaitPoliciesActive(ctx); err != nil {
				t.Fatalf("waiting for policy: %v", err)
			}
			decision, err := o.DryRunCreate(ctx, obj)
			if err != nil {
				t.Fatalf("dry-run create: %v", err)
			}

			clusterDenied := !decision.Allowed
			t.Logf("in-process denied=%v  cluster denied=%v\n  in-process: %s  cluster: %s",
				inProcessDenied, clusterDenied, strings.TrimSpace(oracle.FormatResult(res)), decision)
			if inProcessDenied != clusterDenied {
				t.Errorf("in-process oracle and real apiserver disagree: in-process denied=%v, cluster denied=%v",
					inProcessDenied, clusterDenied)
			}
		})
	}
}

func sanitizeName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 60 {
		out = strings.Trim(out[:60], "-")
	}
	return out
}

func metaV1Zero() metav1.Time { return metav1.Time{} }
