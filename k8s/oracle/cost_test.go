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
	"fmt"
	"sort"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	celconfig "k8s.io/apiserver/pkg/apis/cel"

	"github.com/undistro/cel-playground/oracle"
)

// TestCostMetricsExposure enumerates everything a real apiserver publishes
// about ValidatingAdmissionPolicy evaluation, so the claim "the apiserver does
// not expose per-expression CEL cost" rests on the metric list rather than on
// reading the source and hoping.
func TestCostMetricsExposure(t *testing.T) {
	o := cluster(t)
	ctx := context.Background()

	// Generate some policy traffic first, so the metrics actually exist.
	policy, err := oracle.ParsePolicy(`
kind: ValidatingAdmissionPolicy
metadata:
  name: oracle-metrics-warmup
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["configmaps"]
  validations:
    - expression: "object.metadata.name != 'never-allowed'"
`)
	if err != nil {
		t.Fatalf("parsing warmup policy: %v", err)
	}
	cleanup, err := o.CreatePolicyAndBinding(ctx, policy, nil)
	if err != nil {
		t.Fatalf("installing warmup policy: %v", err)
	}
	defer cleanup()
	if err := o.WaitPoliciesActive(ctx); err != nil {
		t.Fatalf("waiting for warmup policy: %v", err)
	}
	if _, err := o.DryRunCreate(ctx, configMap("metrics-warmup", nil)); err != nil {
		t.Fatalf("warmup request: %v", err)
	}

	raw, err := o.Clientset.CoreV1().RESTClient().Get().AbsPath("/metrics").DoRaw(ctx)
	if err != nil {
		t.Fatalf("fetching /metrics: %v", err)
	}

	var names []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "# HELP ") {
			continue
		}
		rest := strings.TrimPrefix(line, "# HELP ")
		name := rest
		if i := strings.IndexByte(rest, ' '); i > 0 {
			name = rest[:i]
		}
		lower := strings.ToLower(name)
		if !strings.Contains(lower, "admission_policy") && !strings.Contains(lower, "cel") {
			continue
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	sort.Strings(names)

	t.Logf("apiserver metrics mentioning admission_policy or cel (%d):", len(names))
	for _, n := range names {
		t.Logf("  %s", n)
	}

	for _, n := range names {
		if strings.Contains(strings.ToLower(n), "cost") {
			t.Errorf("FOUND a cost metric after all: %s -- the report that cost is unobtainable from metrics is wrong", n)
		}
	}
	t.Logf("CONCLUSION: no metric carries a CEL cost. check_total is a counter and")
	t.Logf("check_duration_seconds is wall-clock latency; neither is the cost integer")
	t.Logf("that activation.go compares against the budget.")
}

// TestCostBudgetBisect establishes what IS obtainable from a real apiserver.
//
// The runtime cost is computed on every evaluation but never reported. The one
// observable is the sharp boundary at the per-binding budget
// (celconfig.RuntimeCELCostBudget). Packing N copies of an expression into one
// policy makes them share a single budget, so the smallest N that trips the
// budget brackets the per-expression cost between B/N and B/(N-1).
//
// The test predicts that N from the exact in-process cost and then confirms the
// prediction on the real apiserver. Agreement means the in-process oracle's
// cost numbers are the same integers a real cluster charges -- which is the
// whole point, because the in-process oracle can report them exactly and for
// far less than a second.
func TestCostBudgetBisect(t *testing.T) {
	o := cluster(t)
	ctx := context.Background()

	// Cost is 6*K+12 for this shape, so K tunes the ballast precisely. K=5000
	// puts the crossover at a few hundred validations: big enough that the
	// bracket is tight, small enough that each admission request stays near one
	// second of CEL.
	const ballast = "lists.range(5000).all(i, i >= 0)"
	budget := int64(celconfig.RuntimeCELCostBudget)

	single, err := oracle.ParsePolicy(`
kind: ValidatingAdmissionPolicy
metadata:
  name: oracle-cost-calibration
spec:
  validations:
    - expression: "` + ballast + `"
`)
	if err != nil {
		t.Fatalf("parsing calibration policy: %v", err)
	}
	obj := configMap("cost-probe", nil)
	costs, err := oracle.ExactCosts(ctx, single, oracle.InProcessRequest{Object: obj})
	if err != nil {
		t.Fatalf("in-process exact cost: %v", err)
	}
	exact := costs.Validations
	t.Logf("in-process exact cost of %q = %d", ballast, exact)
	t.Logf("per-binding runtime budget (celconfig.RuntimeCELCostBudget) = %d", budget)

	// First N whose cumulative cost exceeds the budget.
	predicted := budget/exact + 1
	t.Logf("predicted crossover: %d validations fit, %d exhaust the budget", predicted-1, predicted)

	run := func(n int64) oracle.Decision {
		t.Helper()
		name := fmt.Sprintf("oracle-cost-n%d", n)
		p := &admissionregistrationv1.ValidatingAdmissionPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
				FailurePolicy: ptrTo(admissionregistrationv1.Fail),
				MatchConstraints: &admissionregistrationv1.MatchResources{
					ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{{
						RuleWithOperations: admissionregistrationv1.RuleWithOperations{
							Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
							Rule: admissionregistrationv1.Rule{
								APIGroups:   []string{""},
								APIVersions: []string{"v1"},
								Resources:   []string{"configmaps"},
							},
						},
					}},
				},
			},
		}
		for i := int64(0); i < n; i++ {
			p.Spec.Validations = append(p.Spec.Validations, admissionregistrationv1.Validation{Expression: ballast})
		}
		// The probe ConfigMap must not be caught by this policy or the
		// readiness marker never resolves; exclude it by binding selector.
		binding := oracle.DefaultBinding(name)
		binding.Spec.MatchResources = &admissionregistrationv1.MatchResources{
			ObjectSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      oracle.MarkerLabel,
					Operator: metav1.LabelSelectorOpDoesNotExist,
				}},
			},
		}

		cleanup, err := o.CreatePolicyAndBinding(ctx, p, binding)
		if err != nil {
			t.Fatalf("installing policy with %d validations: %v", n, err)
		}
		defer cleanup()
		if err := o.WaitPoliciesActive(ctx); err != nil {
			t.Fatalf("waiting for policy with %d validations: %v", n, err)
		}
		d, err := o.DryRunCreate(ctx, obj)
		if err != nil {
			t.Fatalf("dry-run create against %d validations: %v", n, err)
		}
		return d
	}

	below := run(predicted - 1)
	t.Logf("N=%d -> %s", predicted-1, below)
	if strings.Contains(below.Message, oracle.OutOfBudgetMessage) {
		t.Errorf("N=%d already exhausted the budget; the in-process cost is too low", predicted-1)
	}

	at := run(predicted)
	t.Logf("N=%d -> %s", predicted, at)
	if !strings.Contains(at.Message, oracle.OutOfBudgetMessage) {
		t.Errorf("N=%d did not exhaust the budget; the in-process cost is too high", predicted)
	}

	lower := budget / predicted
	upper := budget / (predicted - 1)
	t.Logf("CONCLUSION: from the cluster alone the cost is bracketed to (%d, %d]", lower, upper)
	t.Logf("  the in-process oracle reports %d exactly, which is inside that bracket: %v",
		exact, exact > lower && exact <= upper)
	t.Logf("  bracket width is %d (%.2f%% of the cost) and it costs 2 apiserver round trips;",
		upper-lower, 100*float64(upper-lower)/float64(exact))
	t.Logf("  narrowing it further needs a more expensive ballast, which trades")
	t.Logf("  resolution against seconds of CEL per request. Use the in-process oracle.")
}
