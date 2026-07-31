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
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/undistro/cel-playground/oracle"
)

// TestWebhookMatchConditions is the ground truth for match-condition
// evaluation. A webhook's matchConditions decide whether the apiserver calls it
// at all, and the only honest way to observe that decision is to run a real
// webhook and see whether it is called.
//
// Every case installs ONE ValidatingWebhookConfiguration holding two webhooks:
//
//	/probe   - no matchConditions, denies the labelled probe ConfigMap. Because
//	           both webhooks live in the same object they become active at the
//	           same instant, so a fired probe proves the subject webhook is
//	           loaded. Without this, "subject was not called" is ambiguous
//	           between "matchCondition said no" and "not registered yet".
//	/subject - the webhook under test, carrying the matchConditions.
func TestWebhookMatchConditions(t *testing.T) {
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

	cases := []struct {
		name            string
		matchConditions []admissionregistrationv1.MatchCondition
		failurePolicy   admissionregistrationv1.FailurePolicyType
		wantInvoked     bool
		note            string
	}{
		{
			name:            "no matchConditions",
			matchConditions: nil,
			wantInvoked:     true,
		},
		{
			name: "matchCondition true",
			matchConditions: []admissionregistrationv1.MatchCondition{
				{Name: "always", Expression: "true"},
			},
			wantInvoked: true,
		},
		{
			name: "matchCondition false",
			matchConditions: []admissionregistrationv1.MatchCondition{
				{Name: "never", Expression: "false"},
			},
			wantInvoked: false,
		},
		{
			name: "matchCondition on request.resource",
			matchConditions: []admissionregistrationv1.MatchCondition{
				{Name: "only-configmaps", Expression: `request.resource.resource == "configmaps"`},
			},
			wantInvoked: true,
		},
		{
			name: "matchCondition excluding this resource",
			matchConditions: []admissionregistrationv1.MatchCondition{
				{Name: "only-secrets", Expression: `request.resource.resource == "secrets"`},
			},
			wantInvoked: false,
		},
		{
			name: "matchCondition reading the object",
			matchConditions: []admissionregistrationv1.MatchCondition{
				{Name: "labelled", Expression: `has(object.metadata.labels) && "oracle-subject" in object.metadata.labels`},
			},
			wantInvoked: true,
		},
		{
			name: "one of two matchConditions false",
			matchConditions: []admissionregistrationv1.MatchCondition{
				{Name: "yes", Expression: "true"},
				{Name: "no", Expression: "false"},
			},
			wantInvoked: false,
			note:        "matchConditions are ANDed",
		},
		{
			name: "erroring matchCondition with failurePolicy Ignore",
			matchConditions: []admissionregistrationv1.MatchCondition{
				{Name: "boom", Expression: `object.metadata.nonexistent == "x"`},
			},
			failurePolicy: admissionregistrationv1.Ignore,
			wantInvoked:   false,
			note:          "an erroring matchCondition under Ignore skips the webhook",
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ws.Reset()
			probeID := fmt.Sprintf("wh%d", i)
			cfgName := "oracle-webhook-" + sanitizeName(tc.name)

			failurePolicy := tc.failurePolicy
			if failurePolicy == "" {
				failurePolicy = admissionregistrationv1.Fail
			}

			// The probe denies only its own labelled ConfigMap.
			ws.Deny = func(path string, req *admissionv1.AdmissionRequest) string {
				if path == "/probe" {
					return "probe-" + probeID + "-active"
				}
				return ""
			}

			cfg := &admissionregistrationv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: cfgName},
				Webhooks: []admissionregistrationv1.ValidatingWebhook{
					probeWebhook(ws, probeID),
					subjectWebhook(ws, tc.matchConditions, failurePolicy),
				},
			}
			if err := o.CreateRaw(ctx, cfg); err != nil {
				t.Fatalf("creating ValidatingWebhookConfiguration: %v", err)
			}
			defer func() {
				_ = o.Clientset.AdmissionregistrationV1().
					ValidatingWebhookConfigurations().
					Delete(context.Background(), cfgName, metav1.DeleteOptions{})
			}()

			// Wait until the probe fires: both webhooks are then loaded.
			probe := configMap("probe-"+probeID, map[string]string{oracle.MarkerLabel: probeID})
			var lastProbe oracle.Decision
			err := wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 60*time.Second, true,
				func(ctx context.Context) (bool, error) {
					d, err := o.DryRunCreate(ctx, probe)
					if err != nil {
						return false, err
					}
					lastProbe = d
					return !d.Allowed && strings.Contains(d.Message, "probe-"+probeID+"-active"), nil
				})
			if err != nil {
				t.Fatalf("probe webhook never fired (last: %s): %v", lastProbe, err)
			}

			// Everything recorded so far is probe traffic.
			ws.Reset()

			subject := configMap("subject-"+probeID, map[string]string{"oracle-subject": "yes"})
			decision, err := o.DryRunCreate(ctx, subject)
			if err != nil {
				t.Fatalf("dry-run create of subject object: %v", err)
			}

			invoked := len(ws.CallsTo("/subject")) > 0
			t.Logf("matchConditions=%v failurePolicy=%s", exprs(tc.matchConditions), failurePolicy)
			t.Logf("  apiserver decision: %s", decision)
			t.Logf("  /subject webhook invoked: %v (%d call(s))", invoked, len(ws.CallsTo("/subject")))
			for _, c := range ws.CallsTo("/subject") {
				t.Logf("    call: op=%s resource=%s ns=%s name=%s user=%s dryRun=%v",
					c.Operation, c.Resource.Resource, c.Namespace, c.Name, c.Username, c.DryRun)
			}
			if tc.note != "" {
				t.Logf("  note: %s", tc.note)
			}

			if invoked != tc.wantInvoked {
				t.Errorf("webhook invoked = %v, want %v", invoked, tc.wantInvoked)
			}
		})
	}
}

func probeWebhook(ws *oracle.WebhookServer, id string) admissionregistrationv1.ValidatingWebhook {
	return admissionregistrationv1.ValidatingWebhook{
		Name:          "probe.oracle.test",
		FailurePolicy: ptrTo(admissionregistrationv1.Fail),
		SideEffects:   ptrTo(admissionregistrationv1.SideEffectClassNone),
		// Only the labelled probe ConfigMap, so the probe never perturbs the
		// subject request.
		ObjectSelector:          &metav1.LabelSelector{MatchLabels: map[string]string{oracle.MarkerLabel: id}},
		AdmissionReviewVersions: []string{"v1"},
		TimeoutSeconds:          ptrTo(int32(10)),
		Rules:                   configMapRules(),
		ClientConfig: admissionregistrationv1.WebhookClientConfig{
			URL:      ptrTo(ws.URL + "/probe"),
			CABundle: ws.CABundle,
		},
	}
}

func subjectWebhook(ws *oracle.WebhookServer, mc []admissionregistrationv1.MatchCondition, fp admissionregistrationv1.FailurePolicyType) admissionregistrationv1.ValidatingWebhook {
	return admissionregistrationv1.ValidatingWebhook{
		Name:          "subject.oracle.test",
		FailurePolicy: ptrTo(fp),
		SideEffects:   ptrTo(admissionregistrationv1.SideEffectClassNone),
		// Never fire for the probe ConfigMap.
		ObjectSelector: &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key:      oracle.MarkerLabel,
				Operator: metav1.LabelSelectorOpDoesNotExist,
			}},
		},
		AdmissionReviewVersions: []string{"v1"},
		TimeoutSeconds:          ptrTo(int32(10)),
		Rules:                   configMapRules(),
		MatchConditions:         mc,
		ClientConfig: admissionregistrationv1.WebhookClientConfig{
			URL:      ptrTo(ws.URL + "/subject"),
			CABundle: ws.CABundle,
		},
	}
}

func configMapRules() []admissionregistrationv1.RuleWithOperations {
	return []admissionregistrationv1.RuleWithOperations{{
		Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
		Rule: admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"configmaps"},
		},
	}}
}

func configMap(name string, labels map[string]string) *unstructured.Unstructured {
	l := map[string]any{}
	for k, v := range labels {
		l[k] = v
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]any{
			"name":      name,
			"namespace": "default",
			"labels":    l,
		},
		"data": map[string]any{"k": "v"},
	}}
}

func exprs(mc []admissionregistrationv1.MatchCondition) []string {
	if len(mc) == 0 {
		return nil
	}
	out := make([]string, len(mc))
	for i, m := range mc {
		out[i] = m.Name + ": " + m.Expression
	}
	return out
}

func ptrTo[T any](v T) *T { return &v }
