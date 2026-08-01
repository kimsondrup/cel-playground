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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"

	"github.com/undistro/cel-playground/k8s"
	"github.com/undistro/cel-playground/oracle"
)

// webhookParityCase is one row of the playground's own webhook test table
// (k8s/webhook_test.go), so the two suites cover exactly the same corpus.
type webhookParityCase struct {
	name       string
	webhook    string
	orig       string
	updated    string
	request    string
	authorizer string
}

var webhookParityCases = []webhookParityCase{{
	name:    "test a single webhook, match conditions will be successful",
	webhook: "webhook1.yaml",
	updated: "updated1.yaml",
}, {
	name:    "test single webhook, match conditions will not be successful",
	webhook: "webhook2.yaml",
	updated: "updated2.yaml",
}, {
	name:    "test a single webhook, match conditions will rely on request information",
	webhook: "webhook3.yaml",
	updated: "updated3.yaml",
	request: "request3.yaml",
}, {
	name:       "test a single webhook, match conditions will rely on authorizer information",
	webhook:    "webhook4.yaml",
	updated:    "updated4.yaml",
	request:    "request4.yaml",
	authorizer: "authorizer4.yaml",
}, {
	name:       "test multiple webhooks, match conditions will rely on request and authorizer information and will be successful",
	webhook:    "multi webhook1.yaml",
	updated:    "multi updated1.yaml",
	request:    "multi request1.yaml",
	authorizer: "multi authorizer1.yaml",
}, {
	name:       "test multiple webhooks, match conditions will rely on request and authorizer information and will not be successful",
	webhook:    "multi webhook2.yaml",
	updated:    "multi updated2.yaml",
	request:    "multi request2.yaml",
	authorizer: "multi authorizer2.yaml",
}, {
	name:       "test multiple webhooks, match conditions will rely on request and authorizer information with mixed responses",
	webhook:    "multi webhook3.yaml",
	updated:    "multi updated3.yaml",
	request:    "multi request3.yaml",
	authorizer: "multi authorizer3.yaml",
}, {
	name:    "test a single webhook whose match conditions depend on a cluster-faithful decode",
	webhook: "webhook5.yaml",
	updated: "updated5.yaml",
}}

// TestWebhookParityWithUpstream runs the shipped webhook fixtures through the
// playground and through a real apiserver, and compares the one thing a
// matchCondition decides: whether the webhook is called at all.
//
// The playground answers with per-condition CEL results, which is a claim about
// the cluster rather than an observation of it. This turns the claim into the
// prediction the apiserver's own matcher makes from the same results
// (matchconditions/matcher.go: any condition false skips the webhook; otherwise
// an erroring condition rejects the request under Fail and skips the webhook
// under Ignore) and then checks the prediction against a cluster that was given
// the very same configuration, the very same object, the very same user and --
// this is the point of the exercise -- the very same RBAC objects.
//
// The RBAC tab is not simulated. The ClusterRole and ClusterRoleBinding in the
// fixture are created on the cluster, the request is made as the user the
// request tab names via impersonation, and the apiserver's own RBAC authorizer
// answers `authorizer...check("breakglass").allowed()`. The playground's
// hand-rolled authorizer (k8s/authorizer.go) is thereby compared against the
// real one on the same rules.
//
// Every fixture webhook is registered three ways, so that "not called" is never
// ambiguous:
//
//	/case<n>/w<i> - the webhook under test, matchConditions intact.
//	/case<n>/c<i> - the same rules and selectors with NO matchConditions. If
//	                this is not called, the fixture's rules do not match the
//	                fixture's object and the row says nothing about
//	                matchConditions -- which is a test failure, not a pass.
//	/case<n>/any  - one catch-all webhook matching every resource and verb. It
//	                is the readiness signal: the webhook plugin compiles
//	                configurations off an informer, so a request is only
//	                evidence once a webhook from this configuration was dialled
//	                during that same request.
func TestWebhookParityWithUpstream(t *testing.T) {
	o := cluster(t)
	ctx := context.Background()

	ws, err := oracle.StartWebhookServer()
	if err != nil {
		t.Fatalf("starting in-process webhook: %v", err)
	}
	defer func() {
		if err := ws.Stop(); err != nil {
			t.Errorf("stopping webhook server: %v", err)
		}
	}()
	t.Logf("in-process HTTPS webhook listening on %s (self-signed, caBundle %d bytes)", ws.URL, len(ws.CABundle))

	ensureCacheCRD(t, ctx, o)
	grantSubmitters(t, ctx, o, webhookParityCases)

	for i, tc := range webhookParityCases {
		t.Run(tc.name, func(t *testing.T) {
			playground := runWebhookPlayground(t, tc)
			fixture := loadWebhookConfiguration(t, tc.webhook)
			if len(playground.WebhookMatchConditions) != len(fixture.Webhooks) {
				t.Fatalf("the playground reported %d webhooks, the fixture declares %d",
					len(playground.WebhookMatchConditions), len(fixture.Webhooks))
			}

			// Same user the fixture's request tab names, or the envtest admin
			// when the fixture has no request tab.
			client, who := clientForRequest(t, o, tc)
			cleanupRBAC := applyRBAC(t, ctx, o, tc)
			defer cleanupRBAC()

			prefix := fmt.Sprintf("/case%d", i)
			cfgName := fmt.Sprintf("oracle-webhook-parity-%d-%s", i, sanitizeName(tc.name))
			cfg := instrumentedConfiguration(fixture, ws, cfgName, prefix)
			if err := o.CreateRaw(ctx, cfg); err != nil {
				t.Fatalf("creating ValidatingWebhookConfiguration: %v", err)
			}
			defer deleteWebhookConfiguration(t, o, cfgName)

			object := loadWebhookObject(t, tc.updated)
			t.Logf("submitting %s %q as %s", object.GetKind(), object.GetName(), who)

			decision, calls := submitUntilActive(t, ctx, o, ws, client, object, prefix)
			t.Logf("apiserver decision: %s", decision)

			anyRejected := false
			for w := range fixture.Webhooks {
				hook := fixture.Webhooks[w]
				want := predictWebhookCall(playground.WebhookMatchConditions[w], failurePolicyOf(hook))
				anyRejected = anyRejected || want.rejected

				rulesMatch := dialled(calls, prefix+controlPath(w), object.GetName())
				got := dialled(calls, prefix+subjectPath(w), object.GetName())

				t.Logf("webhook[%d] %q failurePolicy=%s", w, hook.Name, failurePolicyOf(hook))
				for _, condition := range playground.WebhookMatchConditions[w] {
					t.Logf("  playground: %s", describeCondition(condition))
				}
				t.Logf("  playground predicts: called=%v rejected=%v (%s)", want.called, want.rejected, want.reason)
				t.Logf("  cluster: called=%v (rules match this object: %v)", got, rulesMatch)

				if !rulesMatch {
					t.Errorf("webhook %q: the twin with the same rules and no matchConditions was never dialled, so the fixture's rules do not match %s %q. This row proves nothing about matchConditions.",
						hook.Name, object.GetKind(), object.GetName())
					continue
				}
				if got != want.called {
					t.Errorf("webhook %q: the playground says the apiserver would%s call it, the apiserver%s. Playground reasoning: %s",
						hook.Name, spokenNot(want.called), spokenDid(got), want.reason)
				}
			}

			// Our handler admits everything, so the only denial the playground
			// predicts is a matchCondition erroring under failurePolicy Fail.
			if anyRejected && decision.Allowed {
				t.Errorf("the playground predicts the request is rejected outright (an erroring matchCondition under failurePolicy Fail), the apiserver allowed it")
			}
			if !anyRejected && !decision.Allowed {
				t.Errorf("the apiserver rejected a request the playground says nothing rejects: %s", decision)
			}
		})
	}
}

// webhookPrediction is what the apiserver's matchconditions matcher would do
// with one webhook's conditions, derived from the playground's results.
type webhookPrediction struct {
	called   bool
	rejected bool
	reason   string
}

// predictWebhookCall reproduces (*matcher).Match. The order matters: a false
// condition wins even when an earlier condition errored, because the matcher
// returns as soon as it sees a false and only consults the failure policy after
// the whole list came back without one.
func predictWebhookCall(results []*k8s.EvalResult, failurePolicy admissionregistrationv1.FailurePolicyType) webhookPrediction {
	errored := ""
	for _, result := range results {
		name := "<unnamed>"
		if result.Name != nil {
			name = *result.Name
		}
		if value, ok := result.Result.(bool); ok && !value {
			return webhookPrediction{reason: fmt.Sprintf("condition %q is false", name)}
		}
		if result.IsError && errored == "" {
			errored = name
		}
	}
	if errored != "" {
		if failurePolicy == admissionregistrationv1.Ignore {
			return webhookPrediction{reason: fmt.Sprintf("condition %q errored, failurePolicy Ignore skips the webhook", errored)}
		}
		return webhookPrediction{rejected: true, reason: fmt.Sprintf("condition %q errored, failurePolicy Fail rejects the request", errored)}
	}
	if len(results) == 0 {
		return webhookPrediction{called: true, reason: "no matchConditions"}
	}
	return webhookPrediction{called: true, reason: "every condition is true"}
}

func describeCondition(result *k8s.EvalResult) string {
	name := "<unnamed>"
	if result.Name != nil {
		name = *result.Name
	}
	if result.IsError {
		message := ""
		if result.Error != nil {
			message = *result.Error
		}
		return fmt.Sprintf("%s = error(%s)", name, message)
	}
	return fmt.Sprintf("%s = %v", name, result.Result)
}

func spokenNot(b bool) string {
	if b {
		return ""
	}
	return " not"
}

func spokenDid(b bool) string {
	if b {
		return " did"
	}
	return " did not"
}

// runWebhookPlayground is the playground half: exactly the call the wasm binary
// makes for the webhook tab.
func runWebhookPlayground(t *testing.T, tc webhookParityCase) k8s.EvalResponse {
	t.Helper()
	out, err := k8s.EvalWebhook(
		readWebhookFixture(t, tc.webhook), readWebhookFixture(t, tc.orig),
		readWebhookFixture(t, tc.updated), readWebhookFixture(t, tc.request),
		readWebhookFixture(t, tc.authorizer))
	if err != nil {
		t.Fatalf("playground eval: %v", err)
	}
	response := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("decoding the playground response: %v", err)
	}
	return response
}

func readWebhookFixture(t *testing.T, name string) []byte {
	t.Helper()
	if name == "" {
		return nil
	}
	data, err := os.ReadFile(oracle.WebhookFixture(name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return data
}

func loadWebhookConfiguration(t *testing.T, name string) *admissionregistrationv1.ValidatingWebhookConfiguration {
	t.Helper()
	cfg := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	if err := yaml.UnmarshalStrict(readWebhookFixture(t, name), cfg); err != nil {
		t.Fatalf("decoding %s: %v", name, err)
	}
	if len(cfg.Webhooks) == 0 {
		t.Fatalf("%s declares no webhooks", name)
	}
	return cfg
}

func loadWebhookObject(t *testing.T, name string) *unstructured.Unstructured {
	t.Helper()
	object, err := oracle.ParseUnstructured(string(readWebhookFixture(t, name)))
	if err != nil {
		t.Fatalf("decoding %s: %v", name, err)
	}
	return object
}

func failurePolicyOf(hook admissionregistrationv1.ValidatingWebhook) admissionregistrationv1.FailurePolicyType {
	if hook.FailurePolicy == nil {
		return admissionregistrationv1.Fail
	}
	return *hook.FailurePolicy
}

func subjectPath(i int) string { return fmt.Sprintf("/w%d", i) }
func controlPath(i int) string { return fmt.Sprintf("/c%d", i) }

const readinessPath = "/any"

// instrumentedConfiguration rewrites the fixture so a cluster can actually run
// it: the clientConfig points at the in-process handler instead of an imaginary
// Service, and admissionReviewVersions -- which the registry requires and the
// fixtures omit -- is filled in. rules, matchPolicy, failurePolicy, sideEffects
// and matchConditions are the fixture's own.
//
// It then adds the twins that make a negative observation meaningful: one
// matchCondition-free copy of each webhook, and one catch-all.
func instrumentedConfiguration(fixture *admissionregistrationv1.ValidatingWebhookConfiguration, ws *oracle.WebhookServer, name, prefix string) *admissionregistrationv1.ValidatingWebhookConfiguration {
	cfg := &admissionregistrationv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: name}}
	for i := range fixture.Webhooks {
		subject := *fixture.Webhooks[i].DeepCopy()
		subject.AdmissionReviewVersions = []string{"v1"}
		subject.TimeoutSeconds = ptrTo(int32(15))
		subject.ClientConfig = admissionregistrationv1.WebhookClientConfig{
			URL:      ptrTo(ws.URL + prefix + subjectPath(i)),
			CABundle: ws.CABundle,
		}
		cfg.Webhooks = append(cfg.Webhooks, subject)

		control := *subject.DeepCopy()
		control.Name = fmt.Sprintf("c%d.control.oracle.test", i)
		control.MatchConditions = nil
		// A control must never change the outcome of the request it is
		// observing, so it is fail-open whatever the fixture says.
		control.FailurePolicy = ptrTo(admissionregistrationv1.Ignore)
		control.ClientConfig.URL = ptrTo(ws.URL + prefix + controlPath(i))
		cfg.Webhooks = append(cfg.Webhooks, control)
	}

	cfg.Webhooks = append(cfg.Webhooks, admissionregistrationv1.ValidatingWebhook{
		Name:                    "any.control.oracle.test",
		FailurePolicy:           ptrTo(admissionregistrationv1.Ignore),
		SideEffects:             ptrTo(admissionregistrationv1.SideEffectClassNone),
		MatchPolicy:             ptrTo(admissionregistrationv1.Equivalent),
		AdmissionReviewVersions: []string{"v1"},
		TimeoutSeconds:          ptrTo(int32(15)),
		Rules: []admissionregistrationv1.RuleWithOperations{{
			Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{"*"},
				APIVersions: []string{"*"},
				Resources:   []string{"*"},
			},
		}},
		ClientConfig: admissionregistrationv1.WebhookClientConfig{
			URL:      ptrTo(ws.URL + prefix + readinessPath),
			CABundle: ws.CABundle,
		},
	})
	return cfg
}

func deleteWebhookConfiguration(t *testing.T, o *oracle.Oracle, name string) {
	t.Helper()
	api := o.Clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations()
	ctx := context.Background()
	if err := api.Delete(ctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		t.Errorf("deleting ValidatingWebhookConfiguration %s: %v", name, err)
		return
	}
	// Leaving it around would let it answer for the next case's request.
	err := wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		_, err := api.Get(ctx, name, metav1.GetOptions{})
		return apierrors.IsNotFound(err), nil
	})
	if err != nil {
		t.Errorf("ValidatingWebhookConfiguration %s did not go away: %v", name, err)
	}
}

// submitUntilActive dry-run creates the object until the catch-all webhook is
// dialled, and returns the calls of that request only. Everything the case then
// concludes comes from a single admission request that provably ran against
// this configuration.
func submitUntilActive(t *testing.T, ctx context.Context, o *oracle.Oracle, ws *oracle.WebhookServer, client dynamic.Interface, object *unstructured.Unstructured, prefix string) (oracle.Decision, []oracle.WebhookCall) {
	t.Helper()
	var (
		decision oracle.Decision
		calls    []oracle.WebhookCall
	)
	err := wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 60*time.Second, true, func(ctx context.Context) (bool, error) {
		ws.Reset()
		d, err := o.DryRunCreateAs(ctx, client, object)
		if err != nil {
			return false, err
		}
		decision, calls = d, ws.Calls()
		if !d.Allowed && strings.Contains(d.Message, "is forbidden:") && strings.Contains(d.Message, "cannot create") {
			// RBAC refused the request itself, which no amount of waiting
			// fixes and which admission never even saw.
			return false, fmt.Errorf("the submitting user is not authorized to create the object: %s", d.Message)
		}
		return dialled(calls, prefix+readinessPath, object.GetName()), nil
	})
	if err != nil {
		t.Fatalf("no webhook from this configuration was ever dialled, so nothing here is evidence (last decision: %s): %v", decision, err)
	}
	return decision, calls
}

// dialled reports whether the apiserver delivered a request for this object to
// this path. Matching on the name as well keeps a stray create elsewhere in the
// suite from being read as a call for the object under test.
func dialled(calls []oracle.WebhookCall, path, name string) bool {
	for _, call := range calls {
		if call.Path != path {
			continue
		}
		if call.Name != "" && call.Name != name {
			continue
		}
		return true
	}
	return false
}

// clientForRequest builds the client that submits the object. With a request
// tab it impersonates the user the tab names, so the apiserver's authorizer
// answers matchConditions for that user; without one it is the envtest admin.
func clientForRequest(t *testing.T, o *oracle.Oracle, tc webhookParityCase) (dynamic.Interface, string) {
	t.Helper()
	request := parseAdmissionRequest(t, tc.request)
	if request == nil {
		return o.Dynamic, "the envtest admin (the fixture has no request tab)"
	}
	user := request.UserInfo
	client, err := o.ImpersonatingClient(rest.ImpersonationConfig{
		UserName: user.Username,
		UID:      user.UID,
		Groups:   user.Groups,
		Extra:    extraValues(user.Extra),
	})
	if err != nil {
		t.Fatalf("building an impersonating client: %v", err)
	}
	return client, fmt.Sprintf("impersonated user %q (groups %v, uid %q)", user.Username, user.Groups, user.UID)
}

func parseAdmissionRequest(t *testing.T, name string) *admissionv1.AdmissionRequest {
	t.Helper()
	data := readWebhookFixture(t, name)
	if len(data) == 0 {
		return nil
	}
	request := &admissionv1.AdmissionRequest{}
	if err := yaml.Unmarshal(data, request); err != nil {
		t.Fatalf("decoding %s: %v", name, err)
	}
	return request
}

// applyRBAC creates the fixture's RBAC tab on the cluster. These are the same
// ClusterRole and ClusterRoleBinding objects the playground hands to its own
// authorizer, so both authorizers answer from one set of rules.
func applyRBAC(t *testing.T, ctx context.Context, o *oracle.Oracle, tc webhookParityCase) func() {
	t.Helper()
	objects := parseRBAC(t, tc.authorizer)
	if len(objects) == 0 {
		if tc.authorizer != "" {
			t.Logf("RBAC tab %s grants nothing", tc.authorizer)
		}
		return func() {}
	}
	var cleanups []func()
	for _, object := range objects {
		if err := o.CreateRaw(ctx, object); err != nil {
			for _, cleanup := range cleanups {
				cleanup()
			}
			t.Fatalf("creating the RBAC objects from %s: %v", tc.authorizer, err)
		}
		cleanups = append(cleanups, deleteRBAC(t, o, object))
	}
	t.Logf("created %d object(s) from RBAC tab %s on the cluster", len(objects), tc.authorizer)
	return func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}
}

func deleteRBAC(t *testing.T, o *oracle.Oracle, object runtime.Object) func() {
	return func() {
		ctx := context.Background()
		var err error
		switch typed := object.(type) {
		case *rbacv1.ClusterRole:
			err = o.Clientset.RbacV1().ClusterRoles().Delete(ctx, typed.Name, metav1.DeleteOptions{})
		case *rbacv1.ClusterRoleBinding:
			err = o.Clientset.RbacV1().ClusterRoleBindings().Delete(ctx, typed.Name, metav1.DeleteOptions{})
		default:
			err = fmt.Errorf("no cleanup for %T", object)
		}
		if err != nil && !apierrors.IsNotFound(err) {
			t.Errorf("deleting %T: %v", object, err)
		}
	}
}

// parseRBAC decodes the multi-document RBAC tab. A tab holding nothing but
// comments -- which is how a fixture says "grant nothing" -- yields no objects.
func parseRBAC(t *testing.T, name string) []runtime.Object {
	t.Helper()
	data := readWebhookFixture(t, name)
	if len(data) == 0 {
		return nil
	}
	var objects []runtime.Object
	reader := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	for {
		document, err := reader.Read()
		if err == io.EOF {
			return objects
		}
		if err != nil {
			t.Fatalf("splitting %s into documents: %v", name, err)
		}
		var probe map[string]any
		if err := yaml.Unmarshal(document, &probe); err != nil {
			t.Fatalf("decoding a document of %s: %v", name, err)
		}
		if len(probe) == 0 {
			continue
		}
		typeMeta := metav1.TypeMeta{}
		if err := yaml.Unmarshal(document, &typeMeta); err != nil {
			t.Fatalf("reading the kind of a document of %s: %v", name, err)
		}
		switch typeMeta.Kind {
		case "ClusterRole":
			object := &rbacv1.ClusterRole{}
			if err := yaml.UnmarshalStrict(document, object); err != nil {
				t.Fatalf("decoding a ClusterRole of %s: %v", name, err)
			}
			objects = append(objects, object)
		case "ClusterRoleBinding":
			object := &rbacv1.ClusterRoleBinding{}
			if err := yaml.UnmarshalStrict(document, object); err != nil {
				t.Fatalf("decoding a ClusterRoleBinding of %s: %v", name, err)
			}
			objects = append(objects, object)
		default:
			t.Fatalf("%s holds a %s, which this test does not know how to create", name, typeMeta.Kind)
		}
	}
}

// grantSubmitters lets the impersonated users create the objects under test.
// The grant is deliberately narrow -- create on the two kinds the fixtures
// submit, and nothing else -- because a broad grant would also authorize the
// "breakglass" check the fixtures' matchConditions make, and every RBAC case
// here would then pass for the wrong reason.
func grantSubmitters(t *testing.T, ctx context.Context, o *oracle.Oracle, cases []webhookParityCase) {
	t.Helper()
	seen := map[string]bool{}
	var subjects []rbacv1.Subject
	for _, tc := range cases {
		request := parseAdmissionRequest(t, tc.request)
		if request == nil || request.UserInfo.Username == "" || seen[request.UserInfo.Username] {
			continue
		}
		seen[request.UserInfo.Username] = true
		subjects = append(subjects, rbacv1.Subject{
			APIGroup: rbacv1.GroupName,
			Kind:     rbacv1.UserKind,
			Name:     request.UserInfo.Username,
		})
	}
	if len(subjects) == 0 {
		return
	}

	const name = "oracle-webhook-parity-submitter"
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"create"},
		}, {
			APIGroups: []string{"example.com"},
			Resources: []string{"caches"},
			Verbs:     []string{"create"},
		}},
	}
	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Subjects:   subjects,
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name},
	}
	for _, object := range []runtime.Object{role, binding} {
		if err := o.CreateRaw(ctx, object); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatalf("granting the impersonated users the right to submit: %v", err)
		}
	}
	t.Cleanup(func() {
		deleteRBAC(t, o, binding)()
		deleteRBAC(t, o, role)()
	})
	t.Logf("granted create on deployments and caches to %d impersonated user(s)", len(subjects))
}

// ensureCacheCRD installs the CRD behind updated5.yaml. That fixture is an
// example.com/v1 Cache, and without the type the apiserver has nothing to admit
// -- the row would silently degrade into "no webhook was dialled".
func ensureCacheCRD(t *testing.T, ctx context.Context, o *oracle.Oracle) {
	t.Helper()
	gvr := schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	crd := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apiextensions.k8s.io/v1",
		"kind":       "CustomResourceDefinition",
		"metadata":   map[string]any{"name": "caches.example.com"},
		"spec": map[string]any{
			"group": "example.com",
			"scope": "Namespaced",
			"names": map[string]any{
				"plural":   "caches",
				"singular": "cache",
				"kind":     "Cache",
				"listKind": "CacheList",
			},
			"versions": []any{map[string]any{
				"name":    "v1",
				"served":  true,
				"storage": true,
				// The fixture's spec is arbitrary, and pruning it would change
				// what the matchConditions see.
				"schema": map[string]any{"openAPIV3Schema": map[string]any{
					"type":                                 "object",
					"x-kubernetes-preserve-unknown-fields": true,
				}},
			}},
		},
	}}
	if _, err := o.Dynamic.Resource(gvr).Create(ctx, crd, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("creating the caches.example.com CRD: %v", err)
	}
	t.Cleanup(func() {
		_ = o.Dynamic.Resource(gvr).Delete(context.Background(), "caches.example.com", metav1.DeleteOptions{})
	})

	err := wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 60*time.Second, true, func(ctx context.Context) (bool, error) {
		o.Mapper.Reset()
		_, err := o.Mapper.RESTMapping(schema.GroupKind{Group: "example.com", Kind: "Cache"}, "v1")
		return err == nil, nil
	})
	if err != nil {
		t.Fatalf("the caches.example.com CRD never became servable: %v", err)
	}
}
