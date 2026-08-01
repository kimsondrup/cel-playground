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
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/yaml"

	"github.com/undistro/cel-playground/k8s/oracle"
)

var mapMarkerSeq atomic.Int64

// parseMAP decodes a MutatingAdmissionPolicy written as YAML.
func parseMAP(t *testing.T, doc string) *admissionregistrationv1.MutatingAdmissionPolicy {
	t.Helper()
	var p admissionregistrationv1.MutatingAdmissionPolicy
	if err := yaml.UnmarshalStrict([]byte(doc), &p); err != nil {
		t.Fatalf("decoding MutatingAdmissionPolicy: %v", err)
	}
	return &p
}

func parseMAPBinding(t *testing.T, doc string) *admissionregistrationv1.MutatingAdmissionPolicyBinding {
	t.Helper()
	var b admissionregistrationv1.MutatingAdmissionPolicyBinding
	if err := yaml.UnmarshalStrict([]byte(doc), &b); err != nil {
		t.Fatalf("decoding MutatingAdmissionPolicyBinding: %v", err)
	}
	return &b
}

// installMAP creates a policy and a binding and registers cleanup. Any create
// error is returned verbatim so a caller testing registry validation can read
// it; on success the returned error is nil.
func installMAP(t *testing.T, o *oracle.Oracle, policy *admissionregistrationv1.MutatingAdmissionPolicy, binding *admissionregistrationv1.MutatingAdmissionPolicyBinding) error {
	t.Helper()
	ctx := context.Background()
	api := o.Clientset.AdmissionregistrationV1()

	if _, err := api.MutatingAdmissionPolicies().Create(ctx, policy, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("creating MutatingAdmissionPolicy %q: %w", policy.Name, err)
	}
	t.Cleanup(func() {
		_ = api.MutatingAdmissionPolicies().Delete(context.Background(), policy.Name, metav1.DeleteOptions{})
	})
	if binding == nil {
		return nil
	}
	if _, err := api.MutatingAdmissionPolicyBindings().Create(ctx, binding, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("creating MutatingAdmissionPolicyBinding %q: %w", binding.Name, err)
	}
	t.Cleanup(func() {
		_ = api.MutatingAdmissionPolicyBindings().Delete(context.Background(), binding.Name, metav1.DeleteOptions{})
	})
	return nil
}

// defaultMAPBinding is a cluster-wide binding for a policy.
func defaultMAPBinding(policyName string) *admissionregistrationv1.MutatingAdmissionPolicyBinding {
	return &admissionregistrationv1.MutatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: policyName + "-binding"},
		Spec: admissionregistrationv1.MutatingAdmissionPolicyBindingSpec{
			PolicyName: policyName,
		},
	}
}

// waitMAPActive blocks until the MutatingAdmissionPolicy admission plugin has
// observed every policy and binding created before this call.
//
// Same trick as Oracle.WaitPoliciesActive, but the marker has to be a
// *mutating* policy: the mutating plugin has its own informer and its own
// compile cache, so a ValidatingAdmissionPolicy marker proves nothing about
// it. The marker adds a label to one uniquely-labelled ConfigMap and the probe
// polls a dry-run CREATE until that label comes back on the returned object.
func waitMAPActive(t *testing.T, o *oracle.Oracle) {
	t.Helper()
	ctx := context.Background()
	id := fmt.Sprintf("m%d", mapMarkerSeq.Add(1))
	name := "oracle-map-marker-" + id

	policy := &admissionregistrationv1.MutatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: admissionregistrationv1.MutatingAdmissionPolicySpec{
			FailurePolicy:      ptrTo(admissionregistrationv1.Fail),
			ReinvocationPolicy: admissionregistrationv1.NeverReinvocationPolicy,
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
			Mutations: []admissionregistrationv1.Mutation{{
				PatchType: admissionregistrationv1.PatchTypeApplyConfiguration,
				ApplyConfiguration: &admissionregistrationv1.ApplyConfiguration{
					Expression: `Object{ metadata: Object.metadata{ labels: {"` + oracle.MarkerLabel + `-seen": "` + id + `"} } }`,
				},
			}},
		},
	}
	binding := &admissionregistrationv1.MutatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name + "-binding"},
		Spec: admissionregistrationv1.MutatingAdmissionPolicyBindingSpec{
			PolicyName: name,
			// Only ever match the probe ConfigMap.
			MatchResources: &admissionregistrationv1.MatchResources{
				ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{oracle.MarkerLabel: id}},
			},
		},
	}
	if err := installMAP(t, o, policy, binding); err != nil {
		t.Fatalf("installing MAP readiness marker: %v", err)
	}

	probe := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]any{
			"name":      name + "-probe",
			"namespace": "default",
			"labels":    map[string]any{oracle.MarkerLabel: id},
		},
	}}
	gvr := configMapGVR
	var last string
	err := wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 60*time.Second, true, func(ctx context.Context) (bool, error) {
		out, err := o.Dynamic.Resource(gvr).Namespace("default").Create(ctx, probe, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
		if err != nil {
			last = err.Error()
			return false, nil
		}
		return out.GetLabels()[oracle.MarkerLabel+"-seen"] == id, nil
	})
	if err != nil {
		t.Fatalf("MAP readiness marker %s never fired (last: %s): %v", id, last, err)
	}
}

// createAndFetch does a real (non-dry-run) CREATE and returns the stored object.
func createAndFetch(t *testing.T, o *oracle.Oracle, obj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	t.Helper()
	ctx := context.Background()
	gvr, namespaced, err := o.MappingFor(obj)
	if err != nil {
		return nil, err
	}
	ns := obj.GetNamespace()
	if namespaced && ns == "" {
		ns = "default"
		obj = obj.DeepCopy()
		obj.SetNamespace(ns)
	}
	ri := o.Dynamic.Resource(gvr)
	var created *unstructured.Unstructured
	if namespaced {
		created, err = ri.Namespace(ns).Create(ctx, obj, metav1.CreateOptions{})
	} else {
		created, err = ri.Create(ctx, obj, metav1.CreateOptions{})
	}
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() {
		if namespaced {
			_ = ri.Namespace(ns).Delete(context.Background(), created.GetName(), metav1.DeleteOptions{})
		} else {
			_ = ri.Delete(context.Background(), created.GetName(), metav1.DeleteOptions{})
		}
	})
	// Read it back from storage rather than trusting the create response.
	if namespaced {
		return ri.Namespace(ns).Get(ctx, created.GetName(), metav1.GetOptions{})
	}
	return ri.Get(ctx, created.GetName(), metav1.GetOptions{})
}

// dryRunCreateObject submits a dry-run CREATE and returns the object the
// apiserver would have stored: admission (including mutation) and defaulting
// have both run, but nothing is persisted.
func dryRunCreateObject(o *oracle.Oracle, obj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	ctx := context.Background()
	gvr, namespaced, err := o.MappingFor(obj)
	if err != nil {
		return nil, err
	}
	ns := obj.GetNamespace()
	if namespaced && ns == "" {
		ns = "default"
		obj = obj.DeepCopy()
		obj.SetNamespace(ns)
	}
	opts := metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}
	if namespaced {
		return o.Dynamic.Resource(gvr).Namespace(ns).Create(ctx, obj, opts)
	}
	return o.Dynamic.Resource(gvr).Create(ctx, obj, opts)
}

func pretty(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}
