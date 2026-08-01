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
	"sort"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilfeature "k8s.io/apiserver/pkg/util/feature"

	genericfeatures "k8s.io/apiserver/pkg/features"
)

var configMapGVR = schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}

// TestMAPFeatureGateDefault reports what this build of k8s.io/apiserver says
// the MutatingAdmissionPolicy gate defaults to.
func TestMAPFeatureGateDefault(t *testing.T) {
	fg := utilfeature.DefaultFeatureGate
	t.Logf("MutatingAdmissionPolicy enabled in this process = %v", fg.Enabled(genericfeatures.MutatingAdmissionPolicy))
	if s, ok := fg.(interface{ KnownFeatures() []string }); ok {
		for _, k := range s.KnownFeatures() {
			if strings.Contains(k, "MutatingAdmissionPolicy") {
				t.Logf("known: %s", k)
			}
		}
	}
}

// TestMAPServedVersions lists every admissionregistration.k8s.io version this
// apiserver serves and which of them carry the Mutating* kinds.
func TestMAPServedVersions(t *testing.T) {
	o := cluster(t)

	groups, err := o.Discovery.ServerGroups()
	if err != nil {
		t.Fatalf("discovering server groups: %v", err)
	}
	for _, g := range groups.Groups {
		if g.Name != "admissionregistration.k8s.io" {
			continue
		}
		t.Logf("group %s preferredVersion=%s", g.Name, g.PreferredVersion.GroupVersion)
		for _, v := range g.Versions {
			list, err := o.Discovery.ServerResourcesForGroupVersion(v.GroupVersion)
			if err != nil {
				t.Errorf("listing %s: %v", v.GroupVersion, err)
				continue
			}
			var names []string
			for _, r := range list.APIResources {
				if strings.Contains(r.Name, "/") {
					continue
				}
				names = append(names, r.Name+" ("+r.Kind+")")
			}
			sort.Strings(names)
			t.Logf("  %s: %s", v.GroupVersion, strings.Join(names, ", "))
		}
	}
}

// TestMAPVersionAcceptance tries to create a MutatingAdmissionPolicy and a
// MutatingAdmissionPolicyBinding in each of the three apiVersions the Go types
// exist for, through the dynamic client so the request really carries that
// version on the wire. It records the exact error for the ones that fail.
func TestMAPVersionAcceptance(t *testing.T) {
	o := cluster(t)
	ctx := context.Background()

	for _, v := range []string{"v1", "v1beta1", "v1alpha1"} {
		for _, kind := range []struct{ kind, resource string }{
			{"MutatingAdmissionPolicy", "mutatingadmissionpolicies"},
			{"MutatingAdmissionPolicyBinding", "mutatingadmissionpolicybindings"},
		} {
			gvr := schema.GroupVersionResource{Group: "admissionregistration.k8s.io", Version: v, Resource: kind.resource}
			name := "oracle-ver-" + strings.ToLower(v) + "-" + strings.ToLower(kind.kind)
			obj := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "admissionregistration.k8s.io/" + v,
				"kind":       kind.kind,
				"metadata":   map[string]any{"name": name},
			}}
			if kind.kind == "MutatingAdmissionPolicy" {
				obj.Object["spec"] = map[string]any{
					"failurePolicy":      "Fail",
					"reinvocationPolicy": "Never",
					"matchConstraints": map[string]any{
						"resourceRules": []any{map[string]any{
							"apiGroups":   []any{""},
							"apiVersions": []any{"v1"},
							"operations":  []any{"CREATE"},
							"resources":   []any{"configmaps"},
						}},
					},
					"mutations": []any{map[string]any{
						"patchType":          "ApplyConfiguration",
						"applyConfiguration": map[string]any{"expression": `Object{metadata: Object.metadata{labels: {"a":"b"}}}`},
					}},
				}
			} else {
				obj.Object["spec"] = map[string]any{"policyName": "does-not-matter"}
			}
			_, err := o.Dynamic.Resource(gvr).Create(ctx, obj, metav1.CreateOptions{})
			if err == nil {
				t.Logf("%s %s: ACCEPTED", v, kind.kind)
				_ = o.Dynamic.Resource(gvr).Delete(ctx, name, metav1.DeleteOptions{})
				continue
			}
			t.Logf("%s %s: REJECTED -- %v", v, kind.kind, err)
		}
	}
}

// TestMAPEndToEnd is the round trip: policy with an applyConfiguration
// mutation and a jsonPatch mutation, a binding, a real CREATE, then the stored
// object read back out of etcd.
func TestMAPEndToEnd(t *testing.T) {
	o := cluster(t)

	policy := parseMAP(t, `
metadata:
  name: oracle-map-e2e
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
    - name: wanted
      expression: "'from-variable'"
  mutations:
    - patchType: ApplyConfiguration
      applyConfiguration:
        expression: >
          Object{
            metadata: Object.metadata{
              labels: {"applyconfig": variables.wanted}
            },
            spec: Object.spec{
              template: Object.spec.template{
                spec: Object.spec.template.spec{
                  containers: [Object.spec.template.spec.containers{
                    name: "app",
                    env: [Object.spec.template.spec.containers.env{name: "ADDED_BY_APPLY", value: "yes"}]
                  }]
                }
              }
            }
          }
    - patchType: JSONPatch
      jsonPatch:
        expression: >
          [
            JSONPatch{op: "add", path: "/metadata/annotations", value: {}},
            JSONPatch{op: "add", path: "/metadata/annotations/" + jsonpatch.escapeKey("oracle.io/patched"), value: "true"},
            JSONPatch{op: "replace", path: "/spec/replicas", value: 7}
          ]
`)
	// Selected by label rather than cluster-wide: every test here shares one
	// apiserver, and a policy that matches every Deployment outlives its own
	// test for as long as the informer takes to notice the delete.
	binding := parseMAPBinding(t, bindingYAML("oracle-map-e2e", "map-e2e", "yes"))
	if err := installMAP(t, o, policy, binding); err != nil {
		t.Fatalf("installing: %v", err)
	}
	waitMAPActive(t, o)

	before := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name": "oracle-map-e2e-dep", "namespace": "default",
			"labels": map[string]any{"map-e2e": "yes"},
		},
		"spec": map[string]any{
			"replicas": int64(1),
			"selector": map[string]any{"matchLabels": map[string]any{"app": "x"}},
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "x"}},
				"spec": map[string]any{
					"containers": []any{map[string]any{"name": "app", "image": "nginx"}},
				},
			},
		},
	}}
	t.Logf("BEFORE (submitted):\n%s", pretty(before.Object))

	after, err := createAndFetch(t, o, before)
	if err != nil {
		t.Fatalf("creating the Deployment: %v", err)
	}
	t.Logf("AFTER (stored, read back with GET):\n%s", pretty(after.Object))

	if got := after.GetLabels()["applyconfig"]; got != "from-variable" {
		t.Errorf("applyConfiguration mutation did not apply: label applyconfig=%q", got)
	}
	if got := after.GetAnnotations()["oracle.io/patched"]; got != "true" {
		t.Errorf("jsonPatch mutation did not apply: annotation oracle.io/patched=%q", got)
	}
	replicas, _, _ := unstructured.NestedInt64(after.Object, "spec", "replicas")
	if replicas != 7 {
		t.Errorf("jsonPatch replace of spec.replicas did not apply: got %d", replicas)
	}
	containers, found, _ := unstructured.NestedSlice(after.Object, "spec", "template", "spec", "containers")
	t.Logf("containers after mutation (found=%v):\n%s", found, pretty(containers))
}
