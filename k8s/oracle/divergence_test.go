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
	"testing"

	"github.com/undistro/cel-playground/k8s"
	"github.com/undistro/cel-playground/oracle"
)

// TestPlaygroundVsUpstreamCost is the differential test the playground's own
// comment in k8s/compiler.go asks for: it runs the SAME fixture through the
// playground's evaluator and through upstream's real validator, and compares
// the total CEL cost each charges.
//
// The playground reports cost as a headline number in the result panel, so a
// cost that does not match what a cluster charges is a user-visible bug: it is
// the number someone uses to decide whether a policy fits the budget.
func TestPlaygroundVsUpstreamCost(t *testing.T) {
	ctx := context.Background()

	fixtures := []struct{ policy, object string }{
		{"variable1 policy.yaml", "variable1 updated.yaml"},
		{"variable2 policy.yaml", "variable2 updated.yaml"},
		{"variable3 policy.yaml", "variable3 updated.yaml"},
		{"variable4 policy.yaml", "variable4 updated.yaml"},
		{"broken1 policy.yaml", "broken1 updated.yaml"},
		{"optional_none_dereference policy.yaml", "optional_none_dereference updated.yaml"},
	}

	for _, f := range fixtures {
		t.Run(f.policy, func(t *testing.T) {
			policyYAML, err := os.ReadFile(oracle.VAPFixture(f.policy))
			if err != nil {
				t.Fatalf("reading policy: %v", err)
			}
			objectYAML, err := os.ReadFile(oracle.VAPFixture(f.object))
			if err != nil {
				t.Fatalf("reading object: %v", err)
			}

			// Playground side.
			out, err := k8s.EvalValidatingAdmissionPolicy(policyYAML, nil, objectYAML, nil, nil, nil)
			if err != nil {
				t.Fatalf("playground eval: %v", err)
			}
			var playground k8s.EvalResponse
			if err := json.Unmarshal([]byte(out), &playground); err != nil {
				t.Fatalf("decoding playground response: %v", err)
			}
			var playgroundCost uint64
			if playground.Cost != nil {
				playgroundCost = *playground.Cost
			}

			// Upstream side.
			policy, err := oracle.LoadPolicy(oracle.VAPFixture(f.policy))
			if err != nil {
				t.Fatalf("loading policy: %v", err)
			}
			obj, err := oracle.LoadUnstructured(oracle.VAPFixture(f.object))
			if err != nil {
				t.Fatalf("loading object: %v", err)
			}
			req := oracle.InProcessRequest{Object: obj}
			costs, err := oracle.ExactCosts(ctx, policy, req)
			if err != nil {
				t.Fatalf("upstream exact costs: %v", err)
			}
			res, err := oracle.Evaluate(ctx, policy, req)
			if err != nil {
				t.Fatalf("upstream evaluate: %v", err)
			}

			// The playground sums every batch into one headline number, so the
			// like-for-like comparison is against upstream's sum -- while noting
			// that the sum is not what any budget is actually checked against.
			upstreamSum := costs.MatchConditions + costs.Validations + costs.MessageExpressions + costs.AuditAnnotations

			t.Logf("playground total cost   = %d", playgroundCost)
			t.Logf("upstream  per-chain     = %s", costs)
			t.Logf("upstream  sum of chains = %d", upstreamSum)
			t.Logf("playground auditAnnotations evaluated: %d", len(playground.AuditAnnotations))
			t.Logf("upstream   auditAnnotations evaluated: %d", len(res.AuditAnnotations))

			if int64(playgroundCost) != upstreamSum {
				t.Errorf("COST DIVERGENCE: playground charges %d, upstream charges %d (delta %d)",
					playgroundCost, upstreamSum, upstreamSum-int64(playgroundCost))
				t.Logf("upstream result:\n%s", oracle.FormatResult(res))
			}
		})
	}
}
