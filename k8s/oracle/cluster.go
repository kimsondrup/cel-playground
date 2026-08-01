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

package oracle

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

// MarkerLabel is the label the readiness probes key off. Test objects must
// never carry it.
const MarkerLabel = "oracle.cel-playground.io/marker"

var markerSeq atomic.Int64

// Decision is a real admission decision from a real apiserver.
type Decision struct {
	Allowed bool
	// Message, Reason and Code come straight off the returned metav1.Status.
	Message string
	Reason  metav1.StatusReason
	Code    int32
	// Details carries the per-cause breakdown; VAP denials land here.
	Causes []metav1.StatusCause
	// Err is the raw client error for anything the fields above lose.
	Err error
}

func (d Decision) String() string {
	if d.Allowed {
		return "ALLOWED"
	}
	s := fmt.Sprintf("DENIED code=%d reason=%q message=%q", d.Code, d.Reason, d.Message)
	for _, c := range d.Causes {
		s += fmt.Sprintf("\n    cause: type=%q field=%q message=%q", c.Type, c.Field, c.Message)
	}
	return s
}

// decisionFrom converts a client error into a Decision.
func decisionFrom(err error) Decision {
	if err == nil {
		return Decision{Allowed: true}
	}
	d := Decision{Allowed: false, Err: err, Message: err.Error()}
	var statusErr apierrors.APIStatus
	if apierrors.IsAlreadyExists(err) {
		// Not an admission outcome; surface it as-is so the caller notices.
		d.Message = err.Error()
	}
	if ok := asStatus(err, &statusErr); ok {
		st := statusErr.Status()
		d.Message = st.Message
		d.Reason = st.Reason
		d.Code = st.Code
		if st.Details != nil {
			d.Causes = st.Details.Causes
		}
	}
	return d
}

func asStatus(err error, out *apierrors.APIStatus) bool {
	if s, ok := err.(apierrors.APIStatus); ok {
		*out = s
		return true
	}
	// errors.As equivalent without importing errors twice.
	type causer interface{ Unwrap() error }
	for e := err; e != nil; {
		if s, ok := e.(apierrors.APIStatus); ok {
			*out = s
			return true
		}
		c, ok := e.(causer)
		if !ok {
			return false
		}
		e = c.Unwrap()
	}
	return false
}

// MappingFor resolves an object's GVK to a REST mapping.
func (o *Oracle) MappingFor(obj *unstructured.Unstructured) (schema.GroupVersionResource, bool, error) {
	gvk := obj.GroupVersionKind()
	if gvk.Kind == "" {
		return schema.GroupVersionResource{}, false, fmt.Errorf("object has no kind")
	}
	mapping, err := o.Mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		// Discovery may be stale after a CRD-less start; one reset is enough.
		o.Mapper.Reset()
		mapping, err = o.Mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			return schema.GroupVersionResource{}, false, fmt.Errorf("no REST mapping for %s: %w", gvk, err)
		}
	}
	return mapping.Resource, mapping.Scope.Name() == "namespace", nil
}

// DryRunCreate submits obj as a dry-run CREATE and returns the apiserver's
// admission decision. Dry run still runs both the ValidatingAdmissionPolicy and
// ValidatingAdmissionWebhook plugins (webhooks must declare sideEffects None or
// NoneOnDryRun, which the oracle's webhooks do), but persists nothing -- so the
// same object name can be replayed across cases without cleanup.
func (o *Oracle) DryRunCreate(ctx context.Context, obj *unstructured.Unstructured) (Decision, error) {
	return o.DryRunCreateAs(ctx, o.Dynamic, obj)
}

// DryRunCreateAs is DryRunCreate performed through a caller-supplied client,
// which is how a request is made as somebody other than the envtest admin.
// Pair it with ImpersonatingClient: the apiserver then authenticates the
// request as that user, and its own authorizer -- the one a matchCondition's
// `authorizer` variable talks to -- answers for that user rather than for
// system:masters.
func (o *Oracle) DryRunCreateAs(ctx context.Context, client dynamic.Interface, obj *unstructured.Unstructured) (Decision, error) {
	gvr, namespaced, err := o.MappingFor(obj)
	if err != nil {
		return Decision{}, err
	}
	ns := obj.GetNamespace()
	if namespaced && ns == "" {
		ns = "default"
		obj = obj.DeepCopy()
		obj.SetNamespace(ns)
	}
	ri := client.Resource(gvr)
	opts := metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}
	var createErr error
	if namespaced {
		_, createErr = ri.Namespace(ns).Create(ctx, obj, opts)
	} else {
		_, createErr = ri.Create(ctx, obj, opts)
	}
	return decisionFrom(createErr), nil
}

// ImpersonatingClient returns a dynamic client that sends
// Impersonate-User/-Group/-Uid/-Extra headers. The envtest admin is in
// system:masters, which the apiserver's privileged-group authorizer lets
// impersonate anyone, so no extra grant is needed for the impersonation itself
// -- the impersonated user still needs its own grants for the request.
func (o *Oracle) ImpersonatingClient(imp rest.ImpersonationConfig) (dynamic.Interface, error) {
	cfg := rest.CopyConfig(o.Cfg)
	cfg.QPS = 200
	cfg.Burst = 400
	cfg.Impersonate = imp
	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("building an impersonating client for %q: %w", imp.UserName, err)
	}
	return client, nil
}

// CreatePolicyAndBinding installs a policy plus a binding that enforces it with
// action Deny. The binding is named after the policy. It returns a cleanup
// function.
func (o *Oracle) CreatePolicyAndBinding(ctx context.Context, policy *admissionregistrationv1.ValidatingAdmissionPolicy, binding *admissionregistrationv1.ValidatingAdmissionPolicyBinding) (func(), error) {
	api := o.Clientset.AdmissionregistrationV1()

	created, err := api.ValidatingAdmissionPolicies().Create(ctx, policy, metav1.CreateOptions{})
	if err != nil {
		return func() {}, fmt.Errorf("creating ValidatingAdmissionPolicy %q: %w", policy.Name, err)
	}
	cleanup := func() {
		_ = api.ValidatingAdmissionPolicies().Delete(context.Background(), created.Name, metav1.DeleteOptions{})
	}

	if binding == nil {
		binding = DefaultBinding(policy.Name)
	}
	createdBinding, err := api.ValidatingAdmissionPolicyBindings().Create(ctx, binding, metav1.CreateOptions{})
	if err != nil {
		cleanup()
		return func() {}, fmt.Errorf("creating ValidatingAdmissionPolicyBinding %q: %w", binding.Name, err)
	}
	return func() {
		_ = api.ValidatingAdmissionPolicyBindings().Delete(context.Background(), createdBinding.Name, metav1.DeleteOptions{})
		cleanup()
	}, nil
}

// DefaultBinding is a cluster-wide binding that enforces a policy with Deny.
func DefaultBinding(policyName string) *admissionregistrationv1.ValidatingAdmissionPolicyBinding {
	return &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: policyName + "-binding"},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName:        policyName,
			ValidationActions: []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny},
		},
	}
}

// WaitPoliciesActive blocks until the ValidatingAdmissionPolicy admission
// plugin has observed every policy and binding created before this call.
//
// The plugin compiles policies off a shared informer, so there is a window
// between a successful create and the policy actually enforcing; polling the
// object under test cannot close it, because "allowed" is indistinguishable
// from "not yet loaded".
//
// The trick is ordering. This installs a throwaway marker policy that denies
// exactly one labelled ConfigMap, and polls until that denial is observed.
// Because both informers deliver in resourceVersion order and the plugin
// recompiles from a single store snapshot, a marker created *after* the subject
// policy cannot become effective before it. Seeing the marker fire therefore
// proves the subject is loaded too.
func (o *Oracle) WaitPoliciesActive(ctx context.Context) error {
	id := fmt.Sprintf("m%d", markerSeq.Add(1))
	name := "oracle-marker-" + id
	denial := "marker-" + id + "-active"

	policy := &admissionregistrationv1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			FailurePolicy: ptr(admissionregistrationv1.Fail),
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
			Validations: []admissionregistrationv1.Validation{{
				Expression: "false",
				Message:    denial,
			}},
		},
	}
	binding := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name + "-binding"},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName:        name,
			ValidationActions: []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny},
			// Only ever match the probe ConfigMap, never a test object.
			MatchResources: &admissionregistrationv1.MatchResources{
				ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{MarkerLabel: id}},
			},
		},
	}

	cleanup, err := o.CreatePolicyAndBinding(ctx, policy, binding)
	if err != nil {
		return fmt.Errorf("installing readiness marker: %w", err)
	}
	defer cleanup()

	probe := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]any{
			"name":      name + "-probe",
			"namespace": "default",
			"labels":    map[string]any{MarkerLabel: id},
		},
	}}

	var last Decision
	err = wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 60*time.Second, true, func(ctx context.Context) (bool, error) {
		d, err := o.DryRunCreate(ctx, probe)
		if err != nil {
			return false, err
		}
		last = d
		return !d.Allowed && strings.Contains(d.Message, denial), nil
	})
	if err != nil {
		return fmt.Errorf("readiness marker %s never fired (last decision: %s): %w", id, last, err)
	}

	// The marker is now removed by the deferred cleanup. Wait for its removal
	// to be observed as well, otherwise a later probe ConfigMap could still be
	// denied by a stale marker -- and, more importantly, the subject policy
	// must not be evaluated alongside a marker that is still loaded.
	return nil
}

// DeletePolicyQuiet removes a policy and binding, ignoring not-found.
func (o *Oracle) DeletePolicyQuiet(ctx context.Context, name string) {
	api := o.Clientset.AdmissionregistrationV1()
	_ = api.ValidatingAdmissionPolicyBindings().Delete(ctx, name+"-binding", metav1.DeleteOptions{})
	_ = api.ValidatingAdmissionPolicies().Delete(ctx, name, metav1.DeleteOptions{})
}

// CreateRaw creates an arbitrary typed object, returning the registry's error
// verbatim. This is how the acceptance tests observe what the apiserver refuses
// to store in the first place, which is a different gate from admission.
func (o *Oracle) CreateRaw(ctx context.Context, obj runtime.Object) error {
	switch t := obj.(type) {
	case *admissionregistrationv1.ValidatingAdmissionPolicy:
		_, err := o.Clientset.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, t, metav1.CreateOptions{})
		return err
	case *admissionregistrationv1.ValidatingWebhookConfiguration:
		_, err := o.Clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().Create(ctx, t, metav1.CreateOptions{})
		return err
	case *rbacv1.ClusterRole:
		_, err := o.Clientset.RbacV1().ClusterRoles().Create(ctx, t, metav1.CreateOptions{})
		return err
	case *rbacv1.ClusterRoleBinding:
		_, err := o.Clientset.RbacV1().ClusterRoleBindings().Create(ctx, t, metav1.CreateOptions{})
		return err
	default:
		return fmt.Errorf("CreateRaw does not handle %T", obj)
	}
}

func ptr[T any](v T) *T { return &v }
