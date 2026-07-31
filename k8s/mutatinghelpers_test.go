// Copyright 2023 Undistro Authors
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
	"context"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func TestGuessResource(t *testing.T) {
	tests := []struct {
		kind string
		want string
	}{
		{"Deployment", "deployments"},
		{"Pod", "pods"},
		{"NetworkPolicy", "networkpolicies"},
		{"Ingress", "ingresses"},
		{"Endpoints", "endpoints"},
		// A trailing "s" does not make a kind plural: these are singular and
		// their resources take -es. Endpoints above is the exception.
		{"ComponentStatus", "componentstatuses"},
		{"Status", "statuses"},
		{"Gateway", "gateways"},
		{"StorageClass", "storageclasses"},
		{"PriorityClass", "priorityclasses"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			if got := guessResource(tt.kind); got != tt.want {
				t.Errorf("guessResource(%q) = %q, want %q", tt.kind, got, tt.want)
			}
		})
	}
}

func TestUnifiedDiff(t *testing.T) {
	tests := []struct {
		name string
		from string
		to   string
		want string
	}{{
		name: "identical documents produce no diff",
		from: "a\nb\n",
		to:   "a\nb\n",
		want: "",
	}, {
		// A zero-length side starts at line 0 in the unified diff format.
		name: "addition to an empty document",
		from: "",
		to:   "a\n",
		want: "--- object\n+++ mutated\n@@ -0,0 +1 @@\n+a\n",
	}, {
		name: "removal down to an empty document",
		from: "a\n",
		to:   "",
		want: "--- object\n+++ mutated\n@@ -1 +0,0 @@\n-a\n",
	}, {
		name: "single line replaced",
		from: "a\n",
		to:   "b\n",
		want: "--- object\n+++ mutated\n@@ -1 +1 @@\n-a\n+b\n",
	}, {
		name: "insertion keeps surrounding context",
		from: "a\nb\nc\n",
		to:   "a\nb\nx\nc\n",
		want: "--- object\n+++ mutated\n@@ -1,3 +1,4 @@\n a\n b\n+x\n c\n",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unifiedDiff(tt.from, tt.to, "object", "mutated"); got != tt.want {
				t.Errorf("unifiedDiff() =\n%q\nwant\n%q", got, tt.want)
			}
		})
	}
}

// splitLines splits a rendered diff into lines, dropping the trailing newline
// so a diff that ends in one does not yield a final empty line.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// TestUnifiedDiffHunkCountsMatchBody guards the @@ headers against drifting out
// of sync with the lines that follow them.
func TestUnifiedDiffHunkCountsMatchBody(t *testing.T) {
	// Far enough apart to stay two hunks: the gap has to exceed twice the
	// context, or the two runs of context meet and the hunks merge.
	const documentLines = 40
	document := make([]string, documentLines)
	for i := range document {
		document[i] = fmt.Sprintf("l%d", i+1)
	}
	from := strings.Join(document, "\n") + "\n"
	edited := append([]string{}, document...)
	edited[1] = "CHANGED"
	edited[documentLines-2] = "CHANGED-NEAR-THE-END"
	to := strings.Join(edited, "\n") + "\n"

	got := unifiedDiff(from, to, "object", "mutated")
	if got == "" {
		t.Fatal("expected a diff")
	}

	lines := splitLines(got)
	if len(lines) < 2 || lines[0] != "--- object" || lines[1] != "+++ mutated" {
		t.Fatalf("missing file headers:\n%s", got)
	}

	var fromCount, toCount, declaredFrom, declaredTo int
	hunks := 0
	check := func() {
		if hunks == 0 {
			return
		}
		if fromCount != declaredFrom || toCount != declaredTo {
			t.Errorf("hunk %d body has %d/%d lines, header declared %d/%d",
				hunks, fromCount, toCount, declaredFrom, declaredTo)
		}
	}

	for _, line := range lines[2:] {
		if strings.HasPrefix(line, "@@ ") {
			check()
			hunks++
			fromCount, toCount = 0, 0
			var fromStart, toStart int
			if _, err := fmt.Sscanf(line, "@@ -%d,%d +%d,%d @@", &fromStart, &declaredFrom, &toStart, &declaredTo); err != nil {
				t.Fatalf("unparseable hunk header %q: %v", line, err)
			}
			continue
		}
		switch line[0] {
		case '+':
			toCount++
		case '-':
			fromCount++
		default:
			fromCount++
			toCount++
		}
	}
	check()

	if hunks != 2 {
		t.Errorf("got %d hunks, want 2 (the two edits are far enough apart to split):\n%s", hunks, got)
	}
}

func TestMutationAuthorizer(t *testing.T) {
	config := &Authorizer{
		Paths: map[string]*PathCheck{
			"/healthz": {Checks: map[string]*Decision{
				"get": {Decision: "allow", Reason: "path-allowed"},
			}},
		},
		Groups: map[string]*GroupCheck{
			"apps": {Resources: map[string]*ResourceCheck{
				"deployments": {
					Checks: map[string]map[string]map[string]*Decision{
						"": {"": {
							"update": {Decision: "allow", Reason: "root-allow"},
							"delete": {Decision: "deny", Reason: "root-deny"},
							"patch":  {Error: "authorization webhook unreachable", Reason: "root-error"},
						}},
						"prod": {"web": {
							"update": {Decision: "allow", Reason: "namespaced-allow"},
						}},
					},
					Subresources: map[string]*ResourceCheck{
						"status": {Checks: map[string]map[string]map[string]*Decision{
							"": {"": {"update": {Decision: "deny", Reason: "subresource-deny"}}},
						}},
					},
				},
			}},
		},
		ServiceAccounts: map[string]map[string]*Authorizer{
			"default": {"builder": {Groups: map[string]*GroupCheck{
				"apps": {Resources: map[string]*ResourceCheck{
					"deployments": {Checks: map[string]map[string]map[string]*Decision{
						"": {"": {"update": {Decision: "allow", Reason: "service-account-allow"}}},
					}},
				}},
			}}},
		},
	}

	tests := []struct {
		name        string
		attributes  authorizer.AttributesRecord
		wantAllowed authorizer.Decision
		wantReason  string
		wantErr     bool
	}{{
		name:        "resource check allows",
		attributes:  authorizer.AttributesRecord{ResourceRequest: true, APIGroup: "apps", Resource: "deployments", Verb: "update"},
		wantAllowed: authorizer.DecisionAllow,
		wantReason:  "root-allow",
	}, {
		name:        "resource check denies",
		attributes:  authorizer.AttributesRecord{ResourceRequest: true, APIGroup: "apps", Resource: "deployments", Verb: "delete"},
		wantAllowed: authorizer.DecisionDeny,
		wantReason:  "root-deny",
	}, {
		name:        "an errored decision keeps its reason",
		attributes:  authorizer.AttributesRecord{ResourceRequest: true, APIGroup: "apps", Resource: "deployments", Verb: "patch"},
		wantAllowed: authorizer.DecisionNoOpinion,
		wantReason:  "root-error",
		wantErr:     true,
	}, {
		name:        "an unknown verb has no opinion",
		attributes:  authorizer.AttributesRecord{ResourceRequest: true, APIGroup: "apps", Resource: "deployments", Verb: "create"},
		wantAllowed: authorizer.DecisionNoOpinion,
	}, {
		name:        "namespace and name select a different entry",
		attributes:  authorizer.AttributesRecord{ResourceRequest: true, APIGroup: "apps", Resource: "deployments", Namespace: "prod", Name: "web", Verb: "update"},
		wantAllowed: authorizer.DecisionAllow,
		wantReason:  "namespaced-allow",
	}, {
		name:        "subresources are resolved",
		attributes:  authorizer.AttributesRecord{ResourceRequest: true, APIGroup: "apps", Resource: "deployments", Subresource: "status", Verb: "update"},
		wantAllowed: authorizer.DecisionDeny,
		wantReason:  "subresource-deny",
	}, {
		name:        "path checks are resolved",
		attributes:  authorizer.AttributesRecord{Path: "/healthz", Verb: "get"},
		wantAllowed: authorizer.DecisionAllow,
		wantReason:  "path-allowed",
	}, {
		name: "a service account user resolves the serviceAccounts section",
		attributes: authorizer.AttributesRecord{
			ResourceRequest: true, APIGroup: "apps", Resource: "deployments", Verb: "update",
			User: &user.DefaultInfo{Name: "system:serviceaccount:default:builder"},
		},
		wantAllowed: authorizer.DecisionAllow,
		wantReason:  "service-account-allow",
	}, {
		name: "an unknown service account gets an empty authorizer, not the root one",
		attributes: authorizer.AttributesRecord{
			ResourceRequest: true, APIGroup: "apps", Resource: "deployments", Verb: "update",
			User: &user.DefaultInfo{Name: "system:serviceaccount:default:unknown"},
		},
		wantAllowed: authorizer.DecisionNoOpinion,
	}, {
		name: "a non-service-account user uses the root authorizer",
		attributes: authorizer.AttributesRecord{
			ResourceRequest: true, APIGroup: "apps", Resource: "deployments", Verb: "update",
			User: &user.DefaultInfo{Name: "alice"},
		},
		wantAllowed: authorizer.DecisionAllow,
		wantReason:  "root-allow",
	}, {
		// The tab matches its keys as they were written, the way the receivers in
		// k8s/authorizer.go do, so a padded attribute is a different key.
		name:        "keys are matched as they were written",
		attributes:  authorizer.AttributesRecord{ResourceRequest: true, APIGroup: " apps ", Resource: " deployments ", Verb: " update "},
		wantAllowed: authorizer.DecisionNoOpinion,
		wantReason:  "",
	}}

	adapter := &mutationAuthorizer{config: config}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, reason, err := adapter.Authorize(context.Background(), tt.attributes)
			if (err != nil) != tt.wantErr {
				t.Errorf("Authorize() error = %v, wantErr %v", err, tt.wantErr)
			}
			if decision != tt.wantAllowed {
				t.Errorf("decision = %v, want %v", decision, tt.wantAllowed)
			}
			if reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// TestMutationAuthorizerNoticesSelectors pins what the adapter does with a
// fieldSelector() / labelSelector() narrowing: it answers from the un-narrowed
// entry anyway, and records that it did so the caller can warn. Without the
// record the wrong answer is silent, since a narrowed check returns an ordinary
// decision.
func TestMutationAuthorizerNoticesSelectors(t *testing.T) {
	fieldRequirements := fields.OneTermEqualSelector("spec.nodeName", "node-a").Requirements()
	labelRequirements, err := labels.ParseToRequirements("env=prod")
	if err != nil {
		t.Fatalf("failed to build label requirements: %v", err)
	}

	base := authorizer.AttributesRecord{
		ResourceRequest: true, APIGroup: "apps", Resource: "deployments", Verb: "update",
	}
	config := &Authorizer{Groups: map[string]*GroupCheck{
		"apps": {Resources: map[string]*ResourceCheck{
			"deployments": {Checks: map[string]map[string]map[string]*Decision{
				"": {"": {"update": {Decision: "allow", Reason: "un-narrowed"}}},
			}},
		}},
	}}

	tests := []struct {
		name         string
		narrow       func(*authorizer.AttributesRecord)
		wantNarrowed bool
	}{{
		name:         "an un-narrowed check is not recorded",
		narrow:       func(*authorizer.AttributesRecord) {},
		wantNarrowed: false,
	}, {
		name: "a field selector is recorded",
		narrow: func(attr *authorizer.AttributesRecord) {
			attr.FieldSelectorRequirements = fieldRequirements
		},
		wantNarrowed: true,
	}, {
		name: "a label selector is recorded",
		narrow: func(attr *authorizer.AttributesRecord) {
			attr.LabelSelectorRequirements = labelRequirements
		},
		wantNarrowed: true,
	}, {
		// Upstream records an unparseable selector on the attributes rather than
		// refusing the call, so ignoring it is the same silence as ignoring a
		// valid one.
		name: "an unparseable selector is recorded",
		narrow: func(attr *authorizer.AttributesRecord) {
			attr.LabelSelectorParsingErr = errors.New("found '!!!', expected: identifier")
		},
		wantNarrowed: true,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attributes := base
			tt.narrow(&attributes)

			adapter := &mutationAuthorizer{config: config, mutation: 2}
			decision, reason, err := adapter.Authorize(context.Background(), attributes)
			if err != nil {
				t.Fatalf("Authorize() error = %v", err)
			}
			// The un-narrowed answer either way: that is the finding, not an
			// aspiration.
			if decision != authorizer.DecisionAllow || reason != "un-narrowed" {
				t.Errorf("Authorize() = (%v, %q), want (Allow, \"un-narrowed\")", decision, reason)
			}

			var want []int
			if tt.wantNarrowed {
				want = []int{2}
			}
			if !reflect.DeepEqual(adapter.narrowedMutations, want) {
				t.Errorf("narrowedMutations = %v, want %v", adapter.narrowedMutations, want)
			}

			// A second check of the same mutation must not be recorded twice: each
			// mutation is evaluated once for its cost and once inside the patcher.
			if _, _, err := adapter.Authorize(context.Background(), attributes); err != nil {
				t.Fatalf("Authorize() error = %v", err)
			}
			if !reflect.DeepEqual(adapter.narrowedMutations, want) {
				t.Errorf("narrowedMutations after a repeat check = %v, want %v", adapter.narrowedMutations, want)
			}
		})
	}
}

func TestMutationAuthorizerWithoutConfig(t *testing.T) {
	adapter := &mutationAuthorizer{}
	decision, reason, err := adapter.Authorize(context.Background(), authorizer.AttributesRecord{
		ResourceRequest: true, APIGroup: "apps", Resource: "deployments", Verb: "update",
	})
	if err != nil || decision != authorizer.DecisionNoOpinion || reason != "" {
		t.Errorf("Authorize() = (%v, %q, %v), want (NoOpinion, \"\", nil)", decision, reason, err)
	}
}

// TestUnifiedDiffFarApartEdits guards the case a full LCS table cannot serve:
// two edits at opposite ends of a large object, where trimming the common
// prefix and suffix leaves nearly the whole document to compare and the table
// goes quadratic in the span between them. That is what takes a browser tab
// down. Myers stays close to the size of the edit, so the diff here is the
// minimal one and cheap to produce.
func TestUnifiedDiffFarApartEdits(t *testing.T) {
	const lines = 20000
	document := make([]string, lines)
	for i := range document {
		document[i] = fmt.Sprintf("  - name: container-%d", i)
	}
	from := strings.Join(document, "\n") + "\n"
	edited := append([]string{}, document...)
	edited[1] = "  - name: EDITED-NEAR-THE-TOP"
	edited[lines-2] = "  - name: EDITED-NEAR-THE-BOTTOM"
	to := strings.Join(edited, "\n") + "\n"

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	got := unifiedDiff(from, to, "object", "mutated")
	runtime.ReadMemStats(&after)

	allocated := after.TotalAlloc - before.TotalAlloc
	const maxAlloc = 32 << 20
	if allocated > maxAlloc {
		t.Errorf("unifiedDiff allocated %d bytes for two one-line edits, want at most %d", allocated, maxAlloc)
	}

	for _, want := range []string{"+  - name: EDITED-NEAR-THE-TOP", "+  - name: EDITED-NEAR-THE-BOTTOM"} {
		if !strings.Contains(got, want) {
			t.Errorf("diff does not contain %q", want)
		}
	}

	// Two hunks of twelve lines -- a hunk header, the removed and added line,
	// diffContextLines of context on the inward side and the one line that
	// exists on the outward side -- plus the two file headers. Anything much
	// larger means the whole document is being reported rather than what
	// changed.
	if want := 2*(1+1+2+diffContextLines) + 2; strings.Count(got, "\n") != want {
		t.Errorf("diff has %d lines, want %d:\n%s", strings.Count(got, "\n"), want, got)
	}
}

// TestUnifiedDiffLargeDocument keeps a one-line change in a large object cheap.
// A quadratic diff would need ~200 MB of browser memory at 5000 lines to report
// the ten lines asserted here. The allocation ceiling is deliberately generous
// -- it is there to catch a quadratic implementation, not to pin a figure.
func TestUnifiedDiffLargeDocument(t *testing.T) {
	const lines = 5000
	document := make([]string, lines)
	for i := range document {
		document[i] = fmt.Sprintf("  - name: container-%d", i)
	}
	from := strings.Join(document, "\n") + "\n"
	inserted := append([]string{}, document[:lines/2]...)
	inserted = append(inserted, "  - name: INSERTED")
	inserted = append(inserted, document[lines/2:]...)
	to := strings.Join(inserted, "\n") + "\n"

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	got := unifiedDiff(from, to, "object", "mutated")
	runtime.ReadMemStats(&after)

	allocated := after.TotalAlloc - before.TotalAlloc
	const maxAlloc = 16 << 20
	if allocated > maxAlloc {
		t.Errorf("unifiedDiff allocated %d bytes for a one-line insertion, want at most %d", allocated, maxAlloc)
	}

	// One insertion, diffContextLines either side, plus the two file headers
	// and the hunk header.
	if want := 1 + 2*diffContextLines + 3; strings.Count(got, "\n") != want {
		t.Errorf("diff has %d lines, want %d:\n%s", strings.Count(got, "\n"), want, got)
	}
	if !strings.Contains(got, "+  - name: INSERTED") {
		t.Errorf("diff does not contain the inserted line:\n%s", got)
	}
	if strings.Contains(got, "-  - name: container-") {
		t.Errorf("diff reports deletions for an insertion-only change:\n%s", got)
	}
	// The hunk must be located at the insertion point, not at line 1.
	if want := fmt.Sprintf("@@ -%d,", lines/2-diffContextLines+1); !strings.Contains(got, want) {
		t.Errorf("diff hunk header is not at the insertion point, want %q:\n%s", want, got)
	}
}

// TestBlankNamespaceTabIsConsistent pins the two decoders that read the
// Namespace tab against each other. deserializeNamespace feeds the
// matchCondition environment and decodeNamespaceObject feeds the mutation
// patchers; cmd/wasm/main.go sends []byte("") for a blank tab, never nil, so if
// only one of them treats empty as absent the same expression answers
// differently in a matchCondition and in a mutation of the same policy.
func TestBlankNamespaceTabIsConsistent(t *testing.T) {
	for _, input := range [][]byte{nil, []byte(""), []byte("   \n")} {
		namespaceMap, err := deserializeNamespace(input)
		if err != nil {
			t.Fatalf("deserializeNamespace(%q) error = %v", input, err)
		}
		namespaceObject, err := decodeNamespaceObject(input)
		if err != nil {
			t.Fatalf("decodeNamespaceObject(%q) error = %v", input, err)
		}
		if (namespaceMap == nil) != (namespaceObject == nil) {
			t.Errorf("input %q: deserializeNamespace nil=%v but decodeNamespaceObject nil=%v -- "+
				"the matchCondition and mutation environments disagree about the same tab",
				input, namespaceMap == nil, namespaceObject == nil)
		}
	}
}

// TestSchemaCoverageBeyondEmbeddedSpecs pins the coverage the generated
// client-go schema buys over the OpenAPI test fixtures that preceded it. A
// group-version without a schema merges lists atomically, which silently
// contradicts what a cluster would do -- so a built-in type falling out of
// coverage is a real regression, not a cosmetic one.
func TestSchemaCoverageBeyondEmbeddedSpecs(t *testing.T) {
	backed := []schema.GroupVersionKind{
		{Version: "v1", Kind: "Pod"},
		{Version: "v1", Kind: "Service"},
		{Group: "apps", Version: "v1", Kind: "Deployment"},
		{Group: "batch", Version: "v1", Kind: "Job"},
		// None of the following had an embedded spec before the switch to the
		// generated schema.
		{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "Role"},
		{Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy"},
		{Group: "policy", Version: "v1", Kind: "PodDisruptionBudget"},
		{Group: "autoscaling", Version: "v2", Kind: "HorizontalPodAutoscaler"},
	}
	for _, gvk := range backed {
		if _, ok := typeConverterFor(gvk); !ok {
			t.Errorf("%s has no schema, so its lists would merge atomically", gvk)
		}
	}

	// A custom resource has no schema anywhere and must still take the deduced
	// path, which is what the missing-schema warning tells the user about.
	crd := schema.GroupVersionKind{Group: "example.com", Version: "v1", Kind: "Widget"}
	if _, ok := typeConverterFor(crd); ok {
		t.Errorf("%s reports a schema, but nothing can know a custom resource's shape", crd)
	}
}

// TestUndeclaredFieldsAreAllReported covers the preserve-and-warn path.
// structured-merge-diff stops walking a map at its first undeclared field, so
// without the pruning loop in undeclaredFields only one of these would surface.
// TestUndeclaredFieldsCompleteBesideAnotherError covers an object that is both
// missing a field from the schema and wrong about a declared one. The probe
// prunes until the parse stops naming undeclared fields, and the parse then
// keeps failing on the type error -- which says nothing about whether any
// undeclared field is left, so the list is complete and must not be reported
// as possibly truncated.
func TestUndeclaredFieldsCompleteBesideAnotherError(t *testing.T) {
	gvk := schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "demo"},
		"spec": map[string]any{
			// Declared, but a string where the schema wants an integer.
			"replicas": "three",
			"alpha":    "1",
		},
	}}
	got, more := undeclaredFields(gvk, object)
	if want := []string{".spec.alpha"}; !reflect.DeepEqual(got, want) {
		t.Errorf("undeclaredFields() = %v, want %v", got, want)
	}
	if more {
		t.Error("undeclaredFields() reported the list as incomplete, want complete -- the parse " +
			"still fails, but on the type error, which hides no undeclared field")
	}
}

func TestUndeclaredFieldsAreAllReported(t *testing.T) {
	gvk := schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "demo", "notAField": "x"},
		"spec": map[string]any{
			"replicas": int64(1),
			"alpha":    "1",
			"beta":     "2",
		},
	}}
	got, more := undeclaredFields(gvk, object)
	want := []string{".metadata.notAField", ".spec.alpha", ".spec.beta"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("undeclaredFields() = %v, want %v", got, want)
	}
	if more {
		t.Error("undeclaredFields() reported the list as incomplete, want complete")
	}

	// A field name containing a dot cannot be pruned, so the walk stops there
	// and has to say the list may be incomplete rather than implying it is not.
	dotted := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "demo"},
		"spec":       map[string]any{"replicas": int64(1), "my.field": "x", "zzz": "y"},
	}}
	if _, more := undeclaredFields(gvk, dotted); !more {
		t.Error("undeclaredFields() reported a complete list after giving up on a dotted field name")
	}

	// A fully declared object must not warn.
	clean := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "demo"},
		"spec":       map[string]any{"replicas": int64(1)},
	}}
	if got, more := undeclaredFields(gvk, clean); got != nil || more {
		t.Errorf("undeclaredFields() on a clean object = %v, %v, want nil, false", got, more)
	}
}
