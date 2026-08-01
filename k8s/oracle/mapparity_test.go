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

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/undistro/cel-playground/k8s/oracle"
)

// TestMAPInProcessMatchesCluster is the differential test: the same policy and
// the same object, once through the in-process patchers and once through a real
// apiserver, compared field by field on what the policy is responsible for.
//
// The two cannot be compared wholesale. The cluster's answer has also been
// through decoding, defaulting, and the rest of the admission chain, and the
// in-process one has not -- that difference is real and is exactly what
// TestMAPDefaultingVsMutation isolates. What must agree is the set of fields
// the policy wrote.
func TestMAPInProcessMatchesCluster(t *testing.T) {
	o := cluster(t)
	ctx := context.Background()

	policy := parseMAP(t, `
metadata:
  name: oracle-map-parity
spec:
  failurePolicy: Fail
  reinvocationPolicy: Never
  matchConstraints:
    resourceRules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["deployments"]
  variables:
    - name: tier
      expression: '"gold"'
  mutations:
    - patchType: ApplyConfiguration
      applyConfiguration:
        expression: >
          Object{
            metadata: Object.metadata{ labels: {"tier": variables.tier} },
            spec: Object.spec{
              template: Object.spec.template{
                spec: Object.spec.template.spec{
                  containers: [Object.spec.template.spec.containers{
                    name: "app",
                    env: [Object.spec.template.spec.containers.env{name: "TIER", value: variables.tier}]
                  }]
                }
              }
            }
          }
    - patchType: JSONPatch
      jsonPatch:
        expression: '[JSONPatch{op: "replace", path: "/spec/replicas", value: 5}]'
`)

	input := func(name string) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]any{"name": name, "namespace": "default", "labels": map[string]any{"map-parity": "yes"}},
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

	inproc, err := oracle.MutateInProcess(ctx, policy, oracle.InProcessRequest{Object: input("parity")}, oracle.StaticTypeConverter())
	if err != nil {
		t.Fatalf("in-process: %v", err)
	}
	t.Logf("in-process exact costs: %s", inproc.Costs)

	if err := installMAP(t, o, policy, parseMAPBinding(t, bindingYAML("oracle-map-parity", "map-parity", "yes"))); err != nil {
		t.Fatalf("installing: %v", err)
	}
	waitMAPActive(t, o)
	fromCluster, err := dryRunCreateObject(o, input("oracle-map-parity-dep"))
	if err != nil {
		t.Fatalf("cluster create: %v", err)
	}

	type probe struct {
		what string
		get  func(*unstructured.Unstructured) any
	}
	probes := []probe{
		{"metadata.labels.tier", func(u *unstructured.Unstructured) any { return u.GetLabels()["tier"] }},
		{"spec.replicas", func(u *unstructured.Unstructured) any {
			v, _, _ := unstructured.NestedInt64(u.Object, "spec", "replicas")
			return v
		}},
		{"container names", func(u *unstructured.Unstructured) any {
			cs, _, _ := unstructured.NestedSlice(u.Object, "spec", "template", "spec", "containers")
			var names []string
			for _, c := range cs {
				names = append(names, c.(map[string]any)["name"].(string))
			}
			return names
		}},
		{"app container env", func(u *unstructured.Unstructured) any {
			cs, _, _ := unstructured.NestedSlice(u.Object, "spec", "template", "spec", "containers")
			for _, c := range cs {
				m := c.(map[string]any)
				if m["name"] == "app" {
					return pretty(m["env"])
				}
			}
			return "<no app container>"
		}},
	}
	for _, p := range probes {
		a, b := pretty(p.get(inproc.Object)), pretty(p.get(fromCluster))
		if a != b {
			t.Errorf("%s DIFFERS\n  in-process: %s\n  cluster:    %s", p.what, a, b)
			continue
		}
		t.Logf("%s agrees: %s", p.what, a)
	}
}
