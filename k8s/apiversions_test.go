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

package k8s

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/api/admissionregistration/v1alpha1"
	"k8s.io/api/admissionregistration/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// extractCelInformation decodes every accepted apiVersion into the v1 types.
// That is only sound while the older versions declare no field the v1 type
// lacks -- a field present in v1beta1 but not v1 would be dropped in silence.
// This test fails the moment a dependency bump breaks that.
func TestAcceptedVersionsAreShapedLikeV1(t *testing.T) {
	tests := []struct {
		version string
		older   any
		v1      any
	}{
		{"v1alpha1", v1alpha1.ValidatingAdmissionPolicy{}, admissionregistrationv1.ValidatingAdmissionPolicy{}},
		{"v1beta1", v1beta1.ValidatingAdmissionPolicy{}, admissionregistrationv1.ValidatingAdmissionPolicy{}},
		{"v1beta1", v1beta1.ValidatingWebhookConfiguration{}, admissionregistrationv1.ValidatingWebhookConfiguration{}},
		{"v1beta1", v1beta1.MutatingWebhookConfiguration{}, admissionregistrationv1.MutatingWebhookConfiguration{}},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%T/%s", tt.v1, tt.version), func(t *testing.T) {
			older := jsonShape(reflect.TypeOf(tt.older))
			target := jsonShape(reflect.TypeOf(tt.v1))
			for _, path := range sortedKeys(older) {
				want, ok := target[path]
				if !ok {
					t.Errorf("%s declares %s, which v1 does not: decoding it into the v1 type would drop it", tt.version, path)
					continue
				}
				if got := older[path]; got != want {
					t.Errorf("%s declares %s as %s, v1 declares it as %s", tt.version, path, got, want)
				}
			}
		})
	}
}

// jsonShape maps every JSON path a type serialises to onto the kind of value
// found there. Types outside the admissionregistration group are shared between
// versions, so they are compared as leaves by name rather than walked.
func jsonShape(t reflect.Type) map[string]string {
	shape := map[string]string{}
	walkJSONShape(t, "", shape, map[reflect.Type]bool{})
	return shape
}

func walkJSONShape(t reflect.Type, prefix string, shape map[string]string, seen map[reflect.Type]bool) {
	cardinality := ""
	for {
		switch t.Kind() {
		case reflect.Pointer:
			t = t.Elem()
			continue
		case reflect.Slice, reflect.Array:
			cardinality += "[]"
			t = t.Elem()
			continue
		}
		break
	}
	if t.Kind() != reflect.Struct || !strings.Contains(t.PkgPath(), "admissionregistration") {
		// A named scalar declared in the group -- FailurePolicyType and the
		// other enums -- is a distinct Go type per version but the same string
		// on the wire, so it is compared by kind. Everything else is a type the
		// versions genuinely share and is compared by name.
		name := t.String()
		if strings.Contains(t.PkgPath(), "admissionregistration") {
			name = t.Kind().String()
		}
		shape[prefix] = cardinality + name
		return
	}
	if seen[t] {
		// A recursive type would otherwise vanish from the comparison; record
		// the cycle so a difference in where it closes still shows up.
		shape[prefix] = cardinality + "cycle:" + t.String()
		return
	}
	seen[t] = true
	defer delete(seen, t)

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		path := prefix + "." + name
		if name == "" && field.Anonymous {
			path = prefix
		}
		walkJSONShape(field.Type, path, shape, seen)
	}
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// A policy written against an older apiVersion reaches the evaluator with every
// CEL expression intact.
func TestOlderApiVersionsCarryTheirExpressions(t *testing.T) {
	for _, version := range []string{"v1alpha1", "v1beta1", "v1"} {
		t.Run(version, func(t *testing.T) {
			policy := fmt.Sprintf(`
apiVersion: admissionregistration.k8s.io/%s
kind: ValidatingAdmissionPolicy
metadata:
  name: policy
spec:
  variables:
    - name: env
      expression: "'prod'"
  matchConditions:
    - name: not-kube-system
      expression: "request.namespace != 'kube-system'"
  validations:
    - expression: "variables.env == 'prod'"
      message: literal
      messageExpression: "'computed'"
  auditAnnotations:
    - key: annotation
      valueExpression: "'value'"
`, version)
			celInfo, err := extractCelInformation([]byte(policy), policyKind)
			if err != nil {
				t.Fatalf("extractCelInformation() error: %v", err)
			}
			want := &CelInformation{
				failurePolicy:          admissionregistrationv1.Fail,
				variables:              []CelVariableInfo{{name: "env", expression: "'prod'"}},
				matchConditions:        []CelMatchConditionsInfo{{name: "not-kube-system", expression: "request.namespace != 'kube-system'"}},
				validations:            []CelValidationInfo{{expression: "variables.env == 'prod'", message: "literal", messageExpression: "'computed'"}},
				auditAnnotations:       []CelAuditAnnotationsInfo{{key: "annotation", expression: "'value'"}},
				webhookMatchConditions: nil,
			}
			if !reflect.DeepEqual(celInfo, want) {
				t.Errorf("extractCelInformation() = %+v, want %+v", celInfo, want)
			}
		})
	}
}

func TestRejectsInputItCannotEvaluate(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{{
		name:    "a kind from another group",
		input:   "apiVersion: apps/v1\nkind: Deployment\n",
		wantErr: `cannot evaluate kind "Deployment"`,
	}, {
		name:    "an apiVersion that has never existed",
		input:   "apiVersion: admissionregistration.k8s.io/v2\nkind: ValidatingAdmissionPolicy\n",
		wantErr: `cannot evaluate apiVersion "admissionregistration.k8s.io/v2"`,
	}, {
		name:    "the right kind in the wrong group",
		input:   "apiVersion: policy/v1\nkind: ValidatingAdmissionPolicy\n",
		wantErr: `expected group admissionregistration.k8s.io`,
	}, {
		name:    "a version that never carried this kind",
		input:   "apiVersion: admissionregistration.k8s.io/v1alpha1\nkind: ValidatingWebhookConfiguration\n",
		wantErr: `cannot evaluate apiVersion "admissionregistration.k8s.io/v1alpha1"`,
	}, {
		name:    "nothing at all",
		input:   "",
		wantErr: "no kind is set",
	}, {
		name:    "not an object",
		input:   "- one\n- two\n",
		wantErr: "failed to decode input",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := extractCelInformation([]byte(tt.input), policyKind)
			if err == nil {
				t.Fatalf("extractCelInformation() succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("extractCelInformation() error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// acceptedVersions is a hand-written list, and k8s.io/api is the authority on
// which versions of these kinds exist. This pins one to the other in both
// directions: a version we accept must still be declared, and a version
// k8s.io/api declares must be one we accept or one we have consciously left
// out.
func TestAcceptedVersionsMatchTheAPI(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		admissionregistrationv1.AddToScheme,
		v1beta1.AddToScheme,
		v1alpha1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatalf("AddToScheme() error: %v", err)
		}
	}

	// Versions of a kind that exist but the playground does not read. A VAP
	// binding carries no CEL, and no v1alpha1 webhook configuration has ever
	// been served.
	declined := map[string]bool{
		"ValidatingWebhookConfiguration/v1alpha1": true,
		"MutatingWebhookConfiguration/v1alpha1":   true,
	}

	for kind, versions := range acceptedVersions {
		for _, version := range versions {
			gvk := schema.GroupVersionKind{Group: admissionregistrationGroup, Version: version, Kind: kind}
			if !scheme.Recognizes(gvk) {
				t.Errorf("acceptedVersions offers %s, which k8s.io/api no longer declares", gvk)
			}
			if err := checkAccepted(metav1.TypeMeta{APIVersion: gvk.GroupVersion().String(), Kind: kind}); err != nil {
				t.Errorf("checkAccepted(%s) error: %v", gvk, err)
			}
		}
	}

	for gvk := range scheme.AllKnownTypes() {
		if gvk.Group != admissionregistrationGroup {
			continue
		}
		if _, ok := acceptedVersions[gvk.Kind]; !ok {
			continue
		}
		if declined[gvk.Kind+"/"+gvk.Version] {
			continue
		}
		if err := checkAccepted(metav1.TypeMeta{APIVersion: gvk.GroupVersion().String(), Kind: gvk.Kind}); err != nil {
			t.Errorf("k8s.io/api declares %s but the playground rejects it: %v", gvk, err)
		}
	}
}

// The apiserver matches field names case-sensitively. Anything looser would
// evaluate a policy here that a cluster reads as empty.
func TestFieldNamesAreCaseSensitive(t *testing.T) {
	policy := `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: cased
spec:
  Validations:
    - Expression: "1 == 1"
  MatchConditions:
    - Name: mc
      Expression: "true"
`
	celInfo, err := extractCelInformation([]byte(policy), policyKind)
	if err != nil {
		t.Fatalf("extractCelInformation() error: %v", err)
	}
	if len(celInfo.validations) != 0 || len(celInfo.matchConditions) != 0 {
		t.Errorf("extractCelInformation() read %d validations and %d matchConditions from capitalised field names; a cluster reads none",
			len(celInfo.validations), len(celInfo.matchConditions))
	}
}

// A whole policy of an older apiVersion evaluates end to end, not just through
// the decoder, because the shipped fixtures are all v1 now.
func TestOlderApiVersionsEvaluate(t *testing.T) {
	object := []byte(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bootcamp
spec:
  replicas: 3
`)
	for _, version := range []string{"v1alpha1", "v1beta1", "v1"} {
		t.Run(version, func(t *testing.T) {
			policy := fmt.Sprintf(`
apiVersion: admissionregistration.k8s.io/%s
kind: ValidatingAdmissionPolicy
metadata:
  name: policy
spec:
  variables:
    - name: replicas
      expression: "object.spec.replicas"
  validations:
    - expression: "variables.replicas >= 3"
`, version)
			out, err := EvalValidatingAdmissionPolicy([]byte(policy), nil, object, nil, nil, nil)
			if err != nil {
				t.Fatalf("EvalValidatingAdmissionPolicy() error: %v", err)
			}
			response := EvalResponse{}
			if err := json.Unmarshal([]byte(out), &response); err != nil {
				t.Fatalf("json.Unmarshal() error: %v", err)
			}
			if len(response.Validations) != 1 || response.Validations[0].Result != true {
				t.Errorf("EvalValidatingAdmissionPolicy() = %s, want one validation that passed", out)
			}
		})
	}
}

// Webhook configurations of both served versions reach the evaluator with their
// matchConditions intact.
func TestWebhookVersionsCarryTheirMatchConditions(t *testing.T) {
	for _, kind := range []string{"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"} {
		for _, version := range []string{"v1", "v1beta1"} {
			t.Run(kind+"/"+version, func(t *testing.T) {
				configuration := fmt.Sprintf(`
apiVersion: admissionregistration.k8s.io/%s
kind: %s
webhooks:
  - name: hook.example.com
    matchConditions:
      - name: not-kube-system
        expression: "request.namespace != 'kube-system'"
`, version, kind)
				celInfo, err := extractCelInformation([]byte(configuration), webhookKinds...)
				if err != nil {
					t.Fatalf("extractCelInformation() error: %v", err)
				}
				want := [][]CelMatchConditionsInfo{{{name: "not-kube-system", expression: "request.namespace != 'kube-system'"}}}
				if !reflect.DeepEqual(celInfo.webhookMatchConditions, want) {
					t.Errorf("extractCelInformation() = %+v, want %+v", celInfo.webhookMatchConditions, want)
				}
			})
		}
	}
}

// A cluster abandons a chain of expressions once it has spent its budget and
// fails the request. The playground keeps going, so that the expression that
// overran is still visible, and reports the overrun instead.
func TestReportsRunningPastACostBudget(t *testing.T) {
	// Every authorizer check costs 350006, and matchConditions have a budget of
	// 2500000, so eight of them run past it.
	conditions := ""
	for i := 0; i < 8; i++ {
		conditions += fmt.Sprintf(`
    - name: check-%d
      expression: 'authorizer.group("apps").resource("deployments").check("get").allowed() || true'`, i)
	}
	policy := `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: expensive
spec:
  matchConditions:` + conditions + `
  validations:
    - expression: "true"
`
	out, err := EvalValidatingAdmissionPolicy([]byte(policy), nil, []byte("apiVersion: apps/v1\nkind: Deployment\n"), nil, nil, nil)
	if err != nil {
		t.Fatalf("EvalValidatingAdmissionPolicy() error: %v", err)
	}
	response := EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if len(response.ExceededBudgets) != 1 {
		t.Fatalf("EvalValidatingAdmissionPolicy() reported %d exceeded budgets, want 1: %s", len(response.ExceededBudgets), out)
	}
	exceeded := response.ExceededBudgets[0]
	if exceeded.Name == nil || *exceeded.Name != "matchConditions" {
		t.Errorf("exceededBudgets[0].name = %v, want matchConditions", exceeded.Name)
	}
	if !exceeded.IsError || exceeded.Error == nil || !strings.Contains(*exceeded.Error, "2500000") {
		t.Errorf("exceededBudgets[0] = %+v, want an error naming the 2500000 budget", exceeded)
	}
}

// The apiserver declares `params` for a policy's expressions exactly when the
// policy declares spec.paramKind, so a policy that has one must compile here
// rather than be rejected for naming a variable a cluster would have declared.
func TestParamsAreDeclaredWithParamKind(t *testing.T) {
	policy := func(paramKind string) string {
		return `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: p
spec:` + paramKind + `
  validations:
    - expression: "params == null"
`
	}
	object := []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\n")

	withKind := `
  paramKind:
    apiVersion: v1
    kind: ConfigMap`
	out, err := EvalValidatingAdmissionPolicy([]byte(policy(withKind)), nil, object, nil, nil, nil)
	if err != nil {
		t.Fatalf("EvalValidatingAdmissionPolicy() error: %v", err)
	}
	response := EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if len(response.Validations) != 1 || response.Validations[0].IsError {
		t.Errorf("a policy with paramKind did not compile: %s", out)
	}

	// Without one, naming `params` is the compilation error a cluster reports.
	out, err = EvalValidatingAdmissionPolicy([]byte(policy("")), nil, object, nil, nil, nil)
	if err != nil {
		t.Fatalf("EvalValidatingAdmissionPolicy() error: %v", err)
	}
	response = EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if len(response.Validations) != 1 || !response.Validations[0].IsError {
		t.Errorf("a policy without paramKind compiled a reference to params: %s", out)
	} else if !strings.Contains(*response.Validations[0].Error, "undeclared reference to 'params'") {
		t.Errorf("unexpected error: %s", *response.Validations[0].Error)
	}
}

// extractPolicyCelInformation and extractMatchConditions read a hand-written
// list of fields. If a Kubernetes bump adds another expression to these types,
// nothing else would notice: the policy would evaluate, quietly missing a
// rule. This enumerates every string field of the v1 types whose name says it
// carries CEL, and fails when that set changes.
func TestEveryExpressionFieldIsAccountedFor(t *testing.T) {
	known := map[string]bool{
		"ValidatingAdmissionPolicySpec.matchConditions[].expression":       true,
		"ValidatingAdmissionPolicySpec.validations[].expression":           true,
		"ValidatingAdmissionPolicySpec.validations[].messageExpression":    true,
		"ValidatingAdmissionPolicySpec.auditAnnotations[].valueExpression": true,
		"ValidatingAdmissionPolicySpec.variables[].expression":             true,
		"ValidatingWebhook.matchConditions[].expression":                   true,
		"MutatingWebhook.matchConditions[].expression":                     true,
		"ValidatingAdmissionPolicySpec.matchConstraints.matchPolicy":       false,
	}
	roots := map[string]reflect.Type{
		"ValidatingAdmissionPolicySpec": reflect.TypeOf(admissionregistrationv1.ValidatingAdmissionPolicySpec{}),
		"ValidatingWebhook":             reflect.TypeOf(admissionregistrationv1.ValidatingWebhook{}),
		"MutatingWebhook":               reflect.TypeOf(admissionregistrationv1.MutatingWebhook{}),
	}

	found := map[string]bool{}
	for name, root := range roots {
		collectExpressionFields(root, name, found, map[reflect.Type]bool{})
	}

	for path := range found {
		if !known[path] {
			t.Errorf("%s carries a CEL expression that extractCelInformation does not read", path)
		}
	}
	for path, isExpression := range known {
		if isExpression && !found[path] {
			t.Errorf("%s is no longer declared; the extractor reads a field that does not exist", path)
		}
	}
}

// collectExpressionFields records every string-typed field whose JSON name ends
// in "expression" or "Expression", which is how this API group names CEL.
func collectExpressionFields(t reflect.Type, prefix string, found map[string]bool, seen map[reflect.Type]bool) {
	cardinality := ""
	for {
		switch t.Kind() {
		case reflect.Pointer:
			t = t.Elem()
			continue
		case reflect.Slice, reflect.Array:
			cardinality = "[]"
			t = t.Elem()
			continue
		}
		break
	}
	if t.Kind() != reflect.Struct || !strings.Contains(t.PkgPath(), "admissionregistration") {
		if t.Kind() == reflect.String && strings.HasSuffix(strings.ToLower(prefix), "expression") {
			found[prefix] = true
		}
		return
	}
	if seen[t] {
		return
	}
	seen[t] = true
	defer delete(seen, t)
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		collectExpressionFields(field.Type, prefix+cardinality+"."+name, found, seen)
	}
}

// A configuration pasted into the policy editor, or a policy pasted into the
// webhook editor, decodes cleanly and carries nothing the other mode reads.
// Saying so beats rendering an empty panel.
func TestEachModeRejectsTheOtherModesKind(t *testing.T) {
	policy := "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingAdmissionPolicy\nmetadata:\n  name: p\nspec:\n  validations:\n    - expression: \"true\"\n"
	configuration := "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingWebhookConfiguration\nwebhooks: []\n"

	if _, err := EvalWebhook([]byte(policy), nil, nil, nil, nil); err == nil {
		t.Errorf("EvalWebhook() accepted a ValidatingAdmissionPolicy")
	} else if !strings.Contains(err.Error(), "belongs in the other one") {
		t.Errorf("EvalWebhook() error = %q", err)
	}

	if _, err := EvalValidatingAdmissionPolicy([]byte(configuration), nil, nil, nil, nil, nil); err == nil {
		t.Errorf("EvalValidatingAdmissionPolicy() accepted a ValidatingWebhookConfiguration")
	} else if !strings.Contains(err.Error(), "belongs in the other one") {
		t.Errorf("EvalValidatingAdmissionPolicy() error = %q", err)
	}
}
