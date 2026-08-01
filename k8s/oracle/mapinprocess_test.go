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

	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/managedfields"

	"github.com/undistro/cel-playground/k8s/oracle"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/server"
)

func deploymentInput() *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "dep", "namespace": "default"},
		"spec": map[string]any{
			"replicas": int64(1),
			"selector": map[string]any{"matchLabels": map[string]any{"app": "x"}},
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "x"}},
				"spec": map[string]any{
					"containers": []any{
						map[string]any{"name": "app", "image": "nginx"},
						map[string]any{"name": "sidecar", "image": "envoy"},
					},
				},
			},
		},
	}}
}

// TestMAPInProcess drives k8s.io/apiserver's own mutating patchers with no
// cluster at all, and reports the exact CEL cost of each mutation.
func TestMAPInProcess(t *testing.T) {
	ctx := context.Background()
	policy := parseMAP(t, `
metadata:
  name: inproc
spec:
  failurePolicy: Fail
  reinvocationPolicy: Never
  matchConstraints:
    resourceRules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["deployments"]
  matchConditions:
    - name: is-default-ns
      expression: "object.metadata.namespace == 'default'"
  mutations:
    - patchType: ApplyConfiguration
      applyConfiguration:
        expression: >
          Object{ metadata: Object.metadata{ labels: {"in": "process"} } }
    - patchType: JSONPatch
      jsonPatch:
        expression: >
          [JSONPatch{op: "replace", path: "/spec/replicas", value: 3}]
`)

	res, err := oracle.MutateInProcess(ctx, policy, oracle.InProcessRequest{
		Object: deploymentInput(),
	}, oracle.StaticTypeConverter())
	if err != nil {
		t.Fatalf("MutateInProcess: %v", err)
	}
	t.Logf("matched=%v perMutationError=%v", res.Matched, res.PerMutationError)
	t.Logf("EXACT COSTS: %s", res.Costs)
	t.Logf("mutated object:\n%s", pretty(res.Object.Object))

	if got := res.Object.GetLabels()["in"]; got != "process" {
		t.Errorf("applyConfiguration did not apply, labels=%v", res.Object.GetLabels())
	}
	r, _, _ := unstructured.NestedInt64(res.Object.Object, "spec", "replicas")
	if r != 3 {
		t.Errorf("jsonPatch did not apply, replicas=%d", r)
	}
	// Both containers must survive: containers is an associative list keyed by
	// name, so a merge that dropped one would prove the type converter was not
	// schema-aware.
	c, _, _ := unstructured.NestedSlice(res.Object.Object, "spec", "template", "spec", "containers")
	if len(c) != 2 {
		t.Errorf("expected 2 containers after merge, got %d: %s", len(c), pretty(c))
	}
}

// TestMAPCostIsProportional shows the reported cost really is the CEL cost and
// not a constant, by scaling the work an expression does.
func TestMAPCostIsProportional(t *testing.T) {
	ctx := context.Background()
	for _, n := range []int{1, 10, 100, 1000} {
		policy := parseMAP(t, `
metadata:
  name: cost
spec:
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
          [JSONPatch{op: "replace", path: "/spec/replicas", value: size(`+rangeExpr(n)+`)}]
`)
		res, err := oracle.MutateInProcess(ctx, policy, oracle.InProcessRequest{Object: deploymentInput()}, oracle.StaticTypeConverter())
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		got, _, _ := unstructured.NestedInt64(res.Object.Object, "spec", "replicas")
		t.Logf("n=%-5d cost=%-8d replicas=%d", n, res.Costs.Mutations[0], got)
	}
}

// TestMAPCostRate measures how long a unit of CEL cost actually takes here, so
// "the cluster timed out" can be told apart from "the budget stopped it".
func TestMAPCostRate(t *testing.T) {
	ctx := context.Background()
	shapes := map[string]string{
		"flat-1000":  "lists.range(1000).all(i, i >= 0)",
		"flat-10000": "lists.range(10000).all(i, i >= 0)",

		"nested-100x100": "lists.range(100).all(i, lists.range(100).all(j, j >= 0))",
		"nested-400x400": "lists.range(400).all(i, lists.range(400).all(j, j >= 0))",
	}
	for name, shape := range shapes {
		policy := parseMAP(t, `
metadata:
  name: rate
spec:
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
        expression: '[JSONPatch{op: "replace", path: "/spec/replicas", value: `+shape+` ? 1 : 2}]'
`)
		start := time.Now()
		res, err := oracle.MutateInProcess(ctx, policy, oracle.InProcessRequest{Object: deploymentInput()}, oracle.StaticTypeConverter())
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		cost := res.Costs.Mutations[0]
		t.Logf("%-16s cost=%-9d wall=%-12s -> %.0f cost units/second err=%v",
			name, cost, elapsed.Round(time.Millisecond), float64(cost)/elapsed.Seconds(), res.PerMutationError[0])
	}
}

func rangeExpr(n int) string {
	// A CEL list comprehension whose cost scales with n.
	return "[" + repeatCSV(n) + "].filter(x, x > 0)"
}

func repeatCSV(n int) string {
	out := ""
	for i := 0; i < n; i++ {
		if i > 0 {
			out += ","
		}
		out += "1"
	}
	return out
}

// TestTypeConverterDeducedVsSchema is the concrete difference between
// managedfields.NewDeducedTypeConverter() and a schema-aware converter, run
// through upstream's own patch.ApplyStructuredMergeDiff.
func TestTypeConverterDeducedVsSchema(t *testing.T) {
	orig := deploymentInput()
	patchObj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{"name": "app", "image": "nginx:1.2.3"},
					},
				},
			},
		},
	}}

	for _, tc := range []struct {
		name string
		conv managedfields.TypeConverter
	}{
		{"schema-aware (client-go applyconfigurations)", oracle.StaticTypeConverter()},
		{"deduced (managedfields.NewDeducedTypeConverter)", managedfields.NewDeducedTypeConverter()},
	} {
		out, err := oracle.ApplySMD(tc.conv, orig, patchObj)
		if err != nil {
			t.Logf("%s: ERROR %v", tc.name, err)
			continue
		}
		c, _, _ := unstructured.NestedSlice(out.Object, "spec", "template", "spec", "containers")
		t.Logf("%s: %d container(s) survive:\n%s", tc.name, len(c), pretty(c))
	}
}

// TestTypeConverterAtomicGuard is the other half of the difference. Upstream's
// ApplyStructuredMergeDiff refuses a patch that touches an atomic list, map or
// struct (patch/smd.go validatePatch -> findAtomics). That guard depends on the
// schema: with a deduced converter nothing resolves to a List with an
// ElementRelationship, so the guard finds no atomics and the merge silently
// replaces the list instead.
func TestTypeConverterAtomicGuard(t *testing.T) {
	orig := deploymentInput()
	// containers[].command has no listType marker, so it is an atomic list.
	patchObj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{"name": "app", "command": []any{"/bin/sh"}},
					},
				},
			},
		},
	}}
	for _, tc := range []struct {
		name string
		conv managedfields.TypeConverter
	}{
		{"schema-aware", oracle.StaticTypeConverter()},
		{"deduced", managedfields.NewDeducedTypeConverter()},
	} {
		out, err := oracle.ApplySMD(tc.conv, orig, patchObj)
		if err != nil {
			t.Logf("%s: REFUSED -- %v", tc.name, err)
			continue
		}
		c, _, _ := unstructured.NestedSlice(out.Object, "spec", "template", "spec", "containers")
		t.Logf("%s: ACCEPTED, containers now:\n%s", tc.name, pretty(c))
	}
}

// The playground arms jsonpatch.AccumulatedCopySizeLimit itself, from a literal
// copy of the apiserver's own default. There is no exported constant to
// reference -- the value is inlined into NewConfig -- so this is what stops the
// copy going stale: build the config the apiserver builds and compare.
//
// Upstream: apiserver/pkg/server/config.go, Config.JSONPatchMaxCopyBytes.
func TestJSONPatchCopyLimitMatchesTheApiserverDefault(t *testing.T) {
	const playgroundLimit = 3 * 1024 * 1024
	config := server.NewConfig(serializer.NewCodecFactory(runtime.NewScheme()))
	if config.JSONPatchMaxCopyBytes != playgroundLimit {
		t.Errorf("the apiserver's JSONPatchMaxCopyBytes is %d and the playground arms %d; update maxAccumulatedCopyBytes in k8s/mutatingadmissionpolicy.go",
			config.JSONPatchMaxCopyBytes, playgroundLimit)
	}
}
