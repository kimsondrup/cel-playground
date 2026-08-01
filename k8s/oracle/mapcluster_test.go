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
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/undistro/cel-playground/k8s/oracle"
)

func cm(name string, data map[string]any) *unstructured.Unstructured {
	obj := map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata":   map[string]any{"name": name, "namespace": "default"},
	}
	if data != nil {
		obj["data"] = data
	}
	return &unstructured.Unstructured{Object: obj}
}

// mapPolicyYAML builds a one-mutation ConfigMap policy.
func mapPolicyYAML(name, reinvocation, matchCondition, jsonPatchExpr string) string {
	mc := ""
	if matchCondition != "" {
		mc = "\n  matchConditions:\n    - name: gate\n      expression: >\n        " + matchCondition
	}
	return fmt.Sprintf(`
metadata:
  name: %s
spec:
  failurePolicy: Fail
  reinvocationPolicy: %s
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["configmaps"]%s
  mutations:
    - patchType: JSONPatch
      jsonPatch:
        expression: >
          %s
`, name, reinvocation, mc, jsonPatchExpr)
}

// bindingYAML binds a policy to objects carrying a marker label, so unrelated
// tests in the same package never see it.
func bindingYAML(policy, selectorLabel, selectorValue string) string {
	return fmt.Sprintf(`
metadata:
  name: %s-binding
spec:
  policyName: %s
  matchResources:
    objectSelector:
      matchLabels:
        %s: %q
`, policy, policy, selectorLabel, selectorValue)
}

func labelled(obj *unstructured.Unstructured, k, v string) *unstructured.Unstructured {
	l := obj.GetLabels()
	if l == nil {
		l = map[string]string{}
	}
	l[k] = v
	obj.SetLabels(l)
	return obj
}

// ---------------------------------------------------------------------------
// 4a. Distinguishing apiserver defaulting from policy mutation
// ---------------------------------------------------------------------------

// TestMAPDefaultingVsMutation runs the identical CREATE twice, once with the
// binding installed and once without, so the diff between the two is exactly
// what the policy did and everything else is defaulting.
func TestMAPDefaultingVsMutation(t *testing.T) {
	o := cluster(t)
	ctx := context.Background()

	dep := func(name string) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]any{"name": name, "namespace": "default", "labels": map[string]any{"map-diff": "yes"}},
			"spec": map[string]any{
				"selector": map[string]any{"matchLabels": map[string]any{"app": "x"}},
				"template": map[string]any{
					"metadata": map[string]any{"labels": map[string]any{"app": "x"}},
					"spec":     map[string]any{"containers": []any{map[string]any{"name": "app", "image": "nginx"}}},
				},
			},
		}}
	}

	// Baseline: no policy at all.
	baseline, err := dryRunCreateObject(o, dep("map-diff-baseline"))
	if err != nil {
		t.Fatalf("baseline create: %v", err)
	}

	policy := parseMAP(t, `
metadata:
  name: oracle-map-diff
spec:
  failurePolicy: Fail
  reinvocationPolicy: Never
  matchConstraints:
    resourceRules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["deployments"]
  mutations:
    - patchType: ApplyConfiguration
      applyConfiguration:
        expression: >
          Object{ spec: Object.spec{ replicas: 4 } }
`)
	binding := parseMAPBinding(t, bindingYAML("oracle-map-diff", "map-diff", "yes"))
	if err := installMAP(t, o, policy, binding); err != nil {
		t.Fatalf("installing: %v", err)
	}
	waitMAPActive(t, o)

	mutated, err := dryRunCreateObject(o, dep("map-diff-mutated"))
	if err != nil {
		t.Fatalf("mutated create: %v", err)
	}
	_ = ctx

	baselineReplicas, _, _ := unstructured.NestedInt64(baseline.Object, "spec", "replicas")
	mutatedReplicas, _, _ := unstructured.NestedInt64(mutated.Object, "spec", "replicas")
	t.Logf("baseline spec.replicas = %d (this is DEFAULTING: nothing in the request set it)", baselineReplicas)
	t.Logf("mutated  spec.replicas = %d (this is the POLICY)", mutatedReplicas)

	// This is the technique TestMAPPlaygroundMatchesCluster rests on: run the
	// same request with and without the binding, and everything that differs is
	// the policy. It only isolates the policy if nothing else moves between the
	// two runs.
	if baselineReplicas != 1 {
		t.Errorf("the unbound request defaulted spec.replicas to %d, want 1", baselineReplicas)
	}
	if mutatedReplicas != 4 {
		t.Errorf("the bound request has spec.replicas %d, want the policy's 4", mutatedReplicas)
	}
	if !sameExceptNameAndReplicas(baseline, mutated) {
		t.Errorf("two dry runs of the same request differ in more than the policy touched:\nbaseline:\n%s\nmutated:\n%s", pretty(baseline), pretty(mutated))
	}
}

func sameExceptNameAndReplicas(a, b *unstructured.Unstructured) bool {
	x, y := a.DeepCopy(), b.DeepCopy()
	for _, o := range []*unstructured.Unstructured{x, y} {
		o.SetName("")
		o.SetCreationTimestamp(metav1.Time{})
		o.SetResourceVersion("")
		o.SetUID("")
		unstructured.RemoveNestedField(o.Object, "metadata", "managedFields")
		unstructured.RemoveNestedField(o.Object, "spec", "replicas")
	}
	return pretty(x.Object) == pretty(y.Object)
}

// ---------------------------------------------------------------------------
// 4b. Does the apiserver report a CEL cost for MAP anywhere?
// ---------------------------------------------------------------------------

// TestMAPMetricsHaveNoCost scrapes the live /metrics endpoint after driving a
// mutation, and prints every mutating_admission_policy series. If a cost
// existed, it would be here.
func TestMAPMetricsHaveNoCost(t *testing.T) {
	o := cluster(t)
	ctx := context.Background()

	policy := parseMAP(t, mapPolicyYAML("oracle-map-metrics", "Never", "",
		`[JSONPatch{op: "add", path: "/data", value: {"m": "1"}}]`))
	binding := parseMAPBinding(t, bindingYAML("oracle-map-metrics", "map-metrics", "yes"))
	if err := installMAP(t, o, policy, binding); err != nil {
		t.Fatalf("installing: %v", err)
	}
	waitMAPActive(t, o)

	if _, err := dryRunCreateObject(o, labelled(cm("oracle-map-metrics-probe", nil), "map-metrics", "yes")); err != nil {
		t.Fatalf("probe create: %v", err)
	}

	raw, err := o.Clientset.RESTClient().Get().AbsPath("/metrics").DoRaw(ctx)
	if err != nil {
		t.Fatalf("scraping /metrics: %v", err)
	}
	var hits []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, "mutating_admission_policy") {
			hits = append(hits, line)
		}
	}
	if len(hits) == 0 {
		t.Errorf("no apiserver_mutating_admission_policy_* series at all -- did the mutation run?")
	}
	for _, h := range hits {
		t.Log(h)
	}
	for _, h := range hits {
		if strings.Contains(h, "cost") || strings.Contains(h, "budget") {
			t.Errorf("a cost/budget metric DOES exist: %s", h)
		}
	}
}

// TestMAPStatusHasNoCost checks the stored policy object for any cost report.
func TestMAPStatusHasNoCost(t *testing.T) {
	o := cluster(t)
	ctx := context.Background()

	policy := parseMAP(t, mapPolicyYAML("oracle-map-status", "Never", "",
		`[JSONPatch{op: "add", path: "/data", value: {"s": "1"}}]`))
	if err := installMAP(t, o, policy, nil); err != nil {
		t.Fatalf("installing: %v", err)
	}
	got, err := o.Clientset.AdmissionregistrationV1().MutatingAdmissionPolicies().Get(ctx, policy.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	t.Logf("stored MutatingAdmissionPolicy (note: no status subresource at all):\n%s", pretty(got))
}

// ---------------------------------------------------------------------------
// 4c. Reinvocation
// ---------------------------------------------------------------------------

// TestMAPReinvocation builds the ping-pong the question asks for: a consumer
// policy whose patch is a no-op until a producer policy has added data.produced.
//
// The consumer must NOT gate itself with a matchCondition. A policy skipped by
// its matchConditions never reaches
// policyReinvokeCtx.AddReinvocablePolicyToPreviouslyInvoked (dispatcher.go
// `continue`s first), so it is not in the reinvocation set and IfNeeded will
// not bring it back. Gating inside the mutation expression instead -- return an
// empty JSON patch list -- keeps the policy "invoked" so it stays eligible.
//
// The test runs the same pair with reinvocationPolicy Never and IfNeeded, and
// repeats each until both orderings of the two policies have been seen, because
// which one runs first is not deterministic (see
// TestMAPOrderingIsNondeterministic).
func TestMAPReinvocation(t *testing.T) {
	o := cluster(t)

	for _, reinvocation := range []string{"Never", "IfNeeded"} {
		t.Run(reinvocation, func(t *testing.T) {
			tag := strings.ToLower(reinvocation)
			consumer := "oracle-consumer-" + tag
			producer := "oracle-producer-" + tag

			pConsumer := parseMAP(t, mapPolicyYAML(consumer, reinvocation, "",
				`has(object.data.produced) ? [JSONPatch{op: "add", path: "/data/consumed", value: "yes"}] : []`))
			pProducer := parseMAP(t, mapPolicyYAML(producer, "Never", "",
				`[JSONPatch{op: "add", path: "/data/produced", value: "yes"}]`))

			if err := installMAP(t, o, pConsumer, parseMAPBinding(t, bindingYAML(consumer, "map-reinvoke", tag))); err != nil {
				t.Fatalf("installing %s: %v", consumer, err)
			}
			if err := installMAP(t, o, pProducer, parseMAPBinding(t, bindingYAML(producer, "map-reinvoke", tag))); err != nil {
				t.Fatalf("installing %s: %v", producer, err)
			}
			waitMAPActive(t, o)

			// Probe until both pass orders have been observed, or give up.
			seen := map[string]int{}
			consumed := 0
			probes := 10
			for i := 0; i < probes; i++ {
				out, err := dryRunCreateObject(o, labelled(cm("oracle-reinvoke-"+tag, map[string]any{"seed": "1"}), "map-reinvoke", tag))
				if err != nil {
					t.Fatalf("create: %v", err)
				}
				data, _, _ := unstructured.NestedStringMap(out.Object, "data")
				if data["consumed"] == "yes" {
					consumed++
				}
				seen[fmt.Sprintf("produced=%s consumed=%s", data["produced"], data["consumed"])]++
				// Force the policy source to recompute its hook list, which
				// reshuffles the order (Go map iteration in
				// generic.policySource.calculatePolicyData).
				waitMAPActive(t, o)
			}
			for k, n := range seen {
				t.Logf("reinvocationPolicy=%s -> %s (x%d)", reinvocation, k, n)
			}
			// IfNeeded brings the consumer back after the producer has run,
			// whichever order they went in, so it consumes every time. Never
			// only consumes when the producer happened to go first, and which
			// that is is not stable -- so only the IfNeeded half is an
			// assertion. The playground says each mutation runs exactly once;
			// this is what that is a departure from.
			if reinvocation == "IfNeeded" && consumed != probes {
				t.Errorf("IfNeeded consumed %d of %d probes; reinvocation did not fire", consumed, probes)
			}
			if reinvocation == "Never" && consumed == probes {
				t.Logf("Never consumed every probe: the producer happened to run first every time, so this run says nothing about Never")
			}
		})
	}
}

// TestMAPOrderingIsNondeterministic is the negative result for "what determines
// mutation order across policies". Nothing does: generic.policySource's
// calculatePolicyData builds the hook list by ranging over a Go map
// (policiesToBindings), so the order is whatever that iteration produced the
// last time the source refreshed. It is stable between refreshes, and a refresh
// happens within a second of any policy or binding change.
func TestMAPOrderingIsNondeterministic(t *testing.T) {
	o := cluster(t)

	letters := []struct{ name, letter string }{
		{"oracle-shuffle-a", "A"},
		{"oracle-shuffle-b", "B"},
		{"oracle-shuffle-c", "C"},
		{"oracle-shuffle-d", "D"},
		{"oracle-shuffle-e", "E"},
	}
	for _, s := range letters {
		expr := `[JSONPatch{op: "replace", path: "/data/order", value: object.data.order + "` + s.letter + `"}]`
		p := parseMAP(t, mapPolicyYAML(s.name, "Never", "", expr))
		if err := installMAP(t, o, p, parseMAPBinding(t, bindingYAML(s.name, "map-shuffle", "yes"))); err != nil {
			t.Fatalf("installing %s: %v", s.name, err)
		}
	}

	seen := map[string]int{}
	for i := 0; i < 6; i++ {
		// waitMAPActive creates and deletes a marker policy, which dirties the
		// source and forces calculatePolicyData to run again.
		waitMAPActive(t, o)
		out, err := dryRunCreateObject(o, labelled(cm("oracle-shuffle-probe", map[string]any{"order": ""}), "map-shuffle", "yes"))
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		v, _, _ := unstructured.NestedString(out.Object, "data", "order")
		seen[v]++
	}
	t.Logf("distinct orders observed over 6 refreshes: %d", len(seen))
	for k, n := range seen {
		t.Logf("  %s x%d", k, n)
	}
}

// ---------------------------------------------------------------------------
// 4d. Ordering
// ---------------------------------------------------------------------------

// TestMAPOrderingAcrossPolicies installs three single-mutation policies whose
// creation order is deliberately not their alphabetical order, each appending
// one letter to the same annotation. The final string is the order the cluster
// applied them in.
func TestMAPOrderingAcrossPolicies(t *testing.T) {
	o := cluster(t)

	// Created third/first/second, named so that alphabetical != creation order.
	specs := []struct{ name, letter string }{
		{"oracle-ord-zulu", "Z"},
		{"oracle-ord-alpha", "A"},
		{"oracle-ord-mike", "M"},
	}
	for _, s := range specs {
		expr := `[JSONPatch{op: "replace", path: "/data/order", value: object.data.order + "` + s.letter + `"}]`
		p := parseMAP(t, mapPolicyYAML(s.name, "Never", "", expr))
		if err := installMAP(t, o, p, parseMAPBinding(t, bindingYAML(s.name, "map-order", "yes"))); err != nil {
			t.Fatalf("installing %s: %v", s.name, err)
		}
	}
	waitMAPActive(t, o)

	for i := 0; i < 3; i++ {
		out, err := dryRunCreateObject(o, labelled(cm("oracle-ord-probe", map[string]any{"order": ""}), "map-order", "yes"))
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		v, _, _ := unstructured.NestedString(out.Object, "data", "order")
		t.Logf("attempt %d: applied order = %q (creation order was Z, A, M; alphabetical is alpha, mike, zulu)", i+1, v)
	}
}

// TestMAPOrderingWithinOnePolicy checks that several mutations in one policy
// run in spec order, and TestMAPOrderingAcrossBindings that two bindings of the
// same policy each get their own invocation.
func TestMAPOrderingWithinOnePolicy(t *testing.T) {
	o := cluster(t)

	policy := parseMAP(t, `
metadata:
  name: oracle-map-inner-order
spec:
  failurePolicy: Fail
  reinvocationPolicy: Never
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["configmaps"]
  mutations:
    - patchType: JSONPatch
      jsonPatch:
        expression: '[JSONPatch{op: "replace", path: "/data/order", value: object.data.order + "1"}]'
    - patchType: JSONPatch
      jsonPatch:
        expression: '[JSONPatch{op: "replace", path: "/data/order", value: object.data.order + "2"}]'
    - patchType: ApplyConfiguration
      applyConfiguration:
        expression: 'Object{ data: {"order": object.data.order + "3"} }'
    - patchType: JSONPatch
      jsonPatch:
        expression: '[JSONPatch{op: "replace", path: "/data/order", value: object.data.order + "4"}]'
`)
	if err := installMAP(t, o, policy, parseMAPBinding(t, bindingYAML("oracle-map-inner-order", "map-inner", "yes"))); err != nil {
		t.Fatalf("installing: %v", err)
	}
	waitMAPActive(t, o)

	out, err := dryRunCreateObject(o, labelled(cm("oracle-inner-probe", map[string]any{"order": ""}), "map-inner", "yes"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	v, _, _ := unstructured.NestedString(out.Object, "data", "order")
	t.Logf("mutations within one policy applied in order %q (spec order is 1,2,3,4)", v)
	if v != "1234" {
		t.Errorf("expected 1234, got %q", v)
	}
}

func TestMAPOrderingAcrossBindings(t *testing.T) {
	o := cluster(t)
	ctx := context.Background()

	name := "oracle-map-twobindings"
	policy := parseMAP(t, mapPolicyYAML(name, "Never", "",
		`[JSONPatch{op: "replace", path: "/data/order", value: object.data.order + "B"}]`))
	if err := installMAP(t, o, policy, parseMAPBinding(t, bindingYAML(name, "map-bind", "yes"))); err != nil {
		t.Fatalf("installing: %v", err)
	}
	second := parseMAPBinding(t, `
metadata:
  name: `+name+`-binding-2
spec:
  policyName: `+name+`
  matchResources:
    objectSelector:
      matchLabels:
        map-bind: "yes"
`)
	if _, err := o.Clientset.AdmissionregistrationV1().MutatingAdmissionPolicyBindings().Create(ctx, second, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating the second binding: %v", err)
	}
	t.Cleanup(func() {
		_ = o.Clientset.AdmissionregistrationV1().MutatingAdmissionPolicyBindings().Delete(context.Background(), second.Name, metav1.DeleteOptions{})
	})
	waitMAPActive(t, o)

	out, err := dryRunCreateObject(o, labelled(cm("oracle-bind-probe", map[string]any{"order": ""}), "map-bind", "yes"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	v, _, _ := unstructured.NestedString(out.Object, "data", "order")
	t.Logf("one policy, two bindings, same object -> %q (one B per binding invocation)", v)
}

// ---------------------------------------------------------------------------
// 4e. A mutation that produces an invalid object
// ---------------------------------------------------------------------------

func TestMAPMutationProducesInvalidObject(t *testing.T) {
	o := cluster(t)

	policy := parseMAP(t, `
metadata:
  name: oracle-map-invalid
spec:
  failurePolicy: Fail
  reinvocationPolicy: Never
  matchConstraints:
    resourceRules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["deployments"]
  mutations:
    - patchType: JSONPatch
      jsonPatch:
        expression: '[JSONPatch{op: "replace", path: "/spec/replicas", value: -5}]'
`)
	if err := installMAP(t, o, policy, parseMAPBinding(t, bindingYAML("oracle-map-invalid", "map-invalid", "yes"))); err != nil {
		t.Fatalf("installing: %v", err)
	}
	waitMAPActive(t, o)

	dep := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "oracle-map-invalid-dep", "namespace": "default", "labels": map[string]any{"map-invalid": "yes"}},
		"spec": map[string]any{
			"replicas": int64(1),
			"selector": map[string]any{"matchLabels": map[string]any{"app": "x"}},
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "x"}},
				"spec":     map[string]any{"containers": []any{map[string]any{"name": "app", "image": "nginx"}}},
			},
		},
	}}
	out, err := dryRunCreateObject(o, dep)
	if err == nil {
		t.Errorf("the apiserver STORED an object the policy made invalid: %s", pretty(out.Object))
		return
	}
	t.Logf("exact error:\n%v", err)
	if st, ok := err.(interface{ Status() metav1.Status }); ok {
		t.Logf("status: %s", pretty(st.Status()))
	}
}

// ---------------------------------------------------------------------------
// 4f. Runtime errors and compile errors
// ---------------------------------------------------------------------------

// TestMAPCompileErrorIsRefusedAtCreate checks which gate rejects a mutation
// expression that does not compile: registry validation at create, or nothing
// until a request arrives.
func TestMAPCompileErrorIsRefusedAtCreate(t *testing.T) {
	o := cluster(t)
	for _, tc := range []struct{ name, expr string }{
		{"syntax", `[JSONPatch{op: "add" path: "/data"}]`},
		{"unknown-object-field", `[JSONPatch{op: "add", path: "/data", value: object.nosuchfield}]`},
		{"unknown-root-variable", `[JSONPatch{op: "add", path: "/data", value: nosuchvariable}]`},
		{"wrong-return", `"not a list of JSONPatch"`},
		{"bad-patch-field", `[JSONPatch{operation: "add", path: "/data", value: "x"}]`},
	} {
		p := parseMAP(t, mapPolicyYAML("oracle-map-compile-"+tc.name, "Never", "", tc.expr))
		err := installMAP(t, o, p, nil)
		if err == nil {
			t.Logf("%s: ACCEPTED at create (the error, if any, is deferred to evaluation)", tc.name)
			continue
		}
		t.Logf("%s: REJECTED at create -- %v", tc.name, err)
	}
}

// TestMAPUnknownObjectFieldAtRuntime is the follow-up: the compiler lets
// object.<anything> through because `object` is dynamically typed, so the
// failure only surfaces on a real request.
func TestMAPUnknownObjectFieldAtRuntime(t *testing.T) {
	o := cluster(t)
	name := "oracle-map-unknownfield"
	p := parseMAP(t, mapPolicyYAML(name, "Never", "",
		`[JSONPatch{op: "add", path: "/data/x", value: string(object.nosuchfield)}]`))
	if err := installMAP(t, o, p, parseMAPBinding(t, bindingYAML(name, "map-unknown", "yes"))); err != nil {
		t.Fatalf("installing: %v", err)
	}
	waitMAPActive(t, o)

	out, err := dryRunCreateObject(o, labelled(cm("oracle-unknown-probe", map[string]any{"seed": "1"}), "map-unknown", "yes"))
	if err != nil {
		t.Logf("runtime result: REJECTED\n%v", err)
		return
	}
	t.Logf("runtime result: ALLOWED, object = %s", pretty(out.Object))
}

// TestMAPRuntimeError drives an expression that compiles but blows up at
// evaluation, with each failurePolicy.
func TestMAPRuntimeError(t *testing.T) {
	o := cluster(t)

	for _, fp := range []string{"Fail", "Ignore"} {
		t.Run(fp, func(t *testing.T) {
			tag := strings.ToLower(fp)
			name := "oracle-map-runtime-" + tag
			doc := fmt.Sprintf(`
metadata:
  name: %s
spec:
  failurePolicy: %s
  reinvocationPolicy: Never
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["configmaps"]
  mutations:
    - patchType: JSONPatch
      jsonPatch:
        expression: '[JSONPatch{op: "add", path: "/data/x", value: object.data["definitely-missing"]}]'
`, name, fp)
			p := parseMAP(t, doc)
			if err := installMAP(t, o, p, parseMAPBinding(t, bindingYAML(name, "map-runtime", tag))); err != nil {
				t.Fatalf("installing: %v", err)
			}
			waitMAPActive(t, o)

			out, err := dryRunCreateObject(o, labelled(cm("oracle-runtime-"+tag, map[string]any{"seed": "1"}), "map-runtime", tag))
			if fp == "Fail" {
				if err == nil {
					t.Fatalf("failurePolicy=Fail admitted a request whose mutation errored: %s", pretty(out.Object))
				}
				t.Logf("failurePolicy=Fail -> request REJECTED:\n%v", err)
				if !strings.Contains(err.Error(), name) {
					t.Errorf("the rejection does not name the policy: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("failurePolicy=Ignore rejected the request: %v", err)
			}
			data, _, _ := unstructured.NestedStringMap(out.Object, "data")
			t.Logf("failurePolicy=Ignore -> request ALLOWED, data=%v", data)
			if _, mutated := data["x"]; mutated {
				t.Errorf("failurePolicy=Ignore applied the mutation that errored: %v", data)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 4g. Does the policy see the defaulted object?
// ---------------------------------------------------------------------------

// TestMAPSeesDefaultedObject mutates based on a field nothing in the request
// sets. If the policy sees the raw submitted object the expression has nothing
// to read; if it sees the defaulted one it can copy the default out.
func TestMAPSeesDefaultedObject(t *testing.T) {
	o := cluster(t)

	policy := parseMAP(t, `
metadata:
  name: oracle-map-defaulted
spec:
  failurePolicy: Fail
  reinvocationPolicy: Never
  matchConstraints:
    resourceRules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["deployments"]
  mutations:
    - patchType: JSONPatch
      jsonPatch:
        expression: >
          [
            JSONPatch{op: "add", path: "/metadata/annotations", value: {}},
            JSONPatch{
              op: "add",
              path: "/metadata/annotations/saw-strategy",
              value: has(object.spec.strategy) && has(object.spec.strategy.type) ? string(object.spec.strategy.type) : "ABSENT"
            },
            JSONPatch{
              op: "add",
              path: "/metadata/annotations/saw-replicas",
              value: has(object.spec.replicas) ? string(object.spec.replicas) : "ABSENT"
            },
            JSONPatch{
              op: "add",
              path: "/metadata/annotations/saw-pullpolicy",
              value: has(object.spec.template.spec.containers[0].imagePullPolicy) ? string(object.spec.template.spec.containers[0].imagePullPolicy) : "ABSENT"
            }
          ]
`)
	if err := installMAP(t, o, policy, parseMAPBinding(t, bindingYAML("oracle-map-defaulted", "map-defaulted", "yes"))); err != nil {
		t.Fatalf("installing: %v", err)
	}
	waitMAPActive(t, o)

	dep := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "oracle-map-defaulted-dep", "namespace": "default", "labels": map[string]any{"map-defaulted": "yes"}},
		"spec": map[string]any{
			// No replicas, no strategy, no imagePullPolicy: all three are
			// supplied by the apiserver's defaulter, not by this request.
			"selector": map[string]any{"matchLabels": map[string]any{"app": "x"}},
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "x"}},
				"spec":     map[string]any{"containers": []any{map[string]any{"name": "app", "image": "nginx"}}},
			},
		},
	}}
	out, err := dryRunCreateObject(o, dep)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	annotations := out.GetAnnotations()
	t.Logf("annotations the policy wrote: %v", annotations)
	// The playground uses the object exactly as typed and says so under
	// notSimulated. This is the claim that makes that caveat necessary: a
	// cluster hands the policy an object three fields richer than the request.
	for key, want := range map[string]string{
		"saw-replicas":   "1",
		"saw-strategy":   "RollingUpdate",
		"saw-pullpolicy": "Always",
	} {
		if annotations[key] != want {
			t.Errorf("%s = %q, want %q: the policy did not see the defaulted object", key, annotations[key], want)
		}
	}
}

// ---------------------------------------------------------------------------
// 4h. Is the cost budget per mutation or per policy?
// ---------------------------------------------------------------------------

// TestMAPBudgetIsPerMutation is the cluster confirmation of what
// mutating/dispatcher.go line 259 says: patcher.Patch is handed
// celconfig.RuntimeCELCostBudget -- the CONSTANT -- once per mutation, not a
// running remainder.
//
// There are TWO limits in play and they have to be kept apart:
//
//   - celconfig.PerCallLimit = 1,000,000 is a cel-go interpreter cost limit
//     compiled into every single expression. Overrunning it aborts that one
//     evaluation with "operation cancelled: actual cost limit exceeded".
//   - celconfig.RuntimeCELCostBudget = 10,000,000 is the budget the caller
//     passes in.
//
// So the experiment cannot be two expensive mutations; it has to be many
// mutations each just under PerCallLimit, adding up past 10,000,000. Twelve at
// ~900,000 each is ~10.8M.
// budgetMutationCount is a var so a run can sweep it; 12 x ~900k is ~10.8M,
// just over RuntimeCELCostBudget.
var budgetMutationCount = 12

// budgetBallast is a JSON patch expression costing ~966,462 -- just under
// celconfig.PerCallLimit (1,000,000) -- and evaluating in ~235 ms.
//
// The shape matters. A flat lists.range(150000) costs about the same but takes
// 30 SECONDS on this machine (see TestMAPCostRate): cost per second collapses
// once the list gets big, and a cluster request built on it dies of the
// apiserver's request timeout long before the cost budget is reached, which
// looks exactly like budget exhaustion in the error. Nesting two small ranges
// buys the same cost at ~4M cost-units/second.
const budgetBallast = `[JSONPatch{op: "replace", path: "/data/order", value: lists.range(400).all(i, lists.range(400).all(j, j >= 0)) ? "y" : "n"}]`

func TestMAPBudgetIsPerMutation(t *testing.T) {
	o := cluster(t)
	ctx := context.Background()

	n := budgetMutationCount
	ballast := budgetBallast

	doc := `
metadata:
  name: oracle-map-budget-many
spec:
  failurePolicy: Fail
  reinvocationPolicy: Never
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["configmaps"]
  mutations:`
	for i := 0; i < n; i++ {
		doc += "\n    - patchType: JSONPatch\n      jsonPatch:\n        expression: '" + ballast + "'"
	}
	many := parseMAP(t, doc)

	res, err := oracle.MutateInProcess(ctx, many, oracle.InProcessRequest{
		Object: cm("budget-probe", map[string]any{"order": ""}),
	}, oracle.StaticTypeConverter())
	if err != nil {
		t.Fatalf("in-process calibration: %v", err)
	}
	t.Logf("in-process exact costs: %s", res.Costs)
	t.Logf("  per-mutation errors: %v", res.PerMutationError)
	t.Logf("  RuntimeCELCostBudget=10000000, PerCallLimit=1000000, total here=%d", res.Costs.Total())

	if err := installMAP(t, o, many, parseMAPBinding(t, bindingYAML("oracle-map-budget-many", "map-budget", "many"))); err != nil {
		t.Fatalf("installing: %v", err)
	}
	waitMAPActive(t, o)
	out, err := dryRunCreateObject(o, labelled(cm("oracle-budget-many", map[string]any{"order": ""}), "map-budget", "many"))
	if err != nil {
		t.Errorf("%d mutations totalling %d were REJECTED, so the budget IS shared across mutations: %v", n, res.Costs.Total(), err)
	} else {
		v, _, _ := unstructured.NestedString(out.Object, "data", "order")
		t.Logf("%d mutations totalling %d: ALLOWED (data.order=%q) -> each mutation gets a FRESH %d budget",
			n, res.Costs.Total(), v, 10000000)
	}

	// Control: a single expression over PerCallLimit is refused. Its message is
	// "operation cancelled: actual cost limit exceeded", which is easy to
	// mistake for budget exhaustion -- it is not the same gate.
	one := parseMAP(t, mapPolicyYAML("oracle-map-budget-percall", "Never", "",
		`[JSONPatch{op: "replace", path: "/data/order", value: lists.range(500).all(i, lists.range(500).all(j, j >= 0)) ? "y" : "n"}]`))
	if err := installMAP(t, o, one, parseMAPBinding(t, bindingYAML("oracle-map-budget-percall", "map-budget", "percall"))); err != nil {
		t.Fatalf("installing: %v", err)
	}
	waitMAPActive(t, o)
	_, err = dryRunCreateObject(o, labelled(cm("oracle-budget-percall", map[string]any{"order": ""}), "map-budget", "percall"))
	if err == nil {
		t.Errorf("a single ~1.5M-cost expression was ALLOWED; PerCallLimit is not being enforced")
	} else {
		t.Logf("single expression over PerCallLimit: REJECTED --\n%v", err)
	}
}

// ---------------------------------------------------------------------------
// 4i. Field ownership
// ---------------------------------------------------------------------------

// TestMAPMutationsAreNotInManagedFields records that a policy's mutations get
// no field manager, which is what the comment in patch/smd.go warns about: the
// fields survive only while the policy is active.
func TestMAPMutationsAreNotInManagedFields(t *testing.T) {
	o := cluster(t)

	policy := parseMAP(t, mapPolicyYAML("oracle-map-fieldmgr", "Never", "",
		`[JSONPatch{op: "add", path: "/data/added-by-policy", value: "yes"}]`))
	if err := installMAP(t, o, policy, parseMAPBinding(t, bindingYAML("oracle-map-fieldmgr", "map-fieldmgr", "yes"))); err != nil {
		t.Fatalf("installing: %v", err)
	}
	waitMAPActive(t, o)

	stored, err := createAndFetch(t, o, labelled(cm("oracle-fieldmgr-probe", map[string]any{"mine": "1"}), "map-fieldmgr", "yes"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	data, _, _ := unstructured.NestedStringMap(stored.Object, "data")
	t.Logf("stored data = %v", data)
	t.Logf("managedFields =\n%s", pretty(stored.Object["metadata"].(map[string]any)["managedFields"]))
}
