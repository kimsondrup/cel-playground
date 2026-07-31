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
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

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
