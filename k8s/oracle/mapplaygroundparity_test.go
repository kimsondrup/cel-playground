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
	"os"
	"strconv"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
	"sigs.k8s.io/yaml"

	"github.com/undistro/cel-playground/k8s"
	"github.com/undistro/cel-playground/k8s/oracle"
)

// mapParityCase is one row of the shipped map corpus: the same tabs the unit
// tests feed the playground.
type mapParityCase struct {
	policy    string
	object    string
	oldObject string
	namespace string
	request   string
	rbac      string
	// wantFailures is the number of mutations expected to fail. A failure is
	// still parity -- upstream has to fail in the same place -- but a corpus
	// that quietly stopped mutating would otherwise look like agreement.
	wantFailures int
}

// TestMAPPlaygroundMatchesUpstream runs the whole shipped map corpus through the
// playground and through upstream's own patchers, and compares the object each
// produced and what each mutation was charged.
//
// This is the differential test the mutating mode is built around. The
// playground reproduces mutating.compilePolicy out of exported parts, because
// the package itself is +8.96 MB gzip and reaches a fake clientset; the oracle
// reproduces it too, independently, in a module where importing the real thing
// is free -- and additionally drives the mutation with client-go's own
// generated merge schema rather than the copy the binary embeds. Two
// reproductions that agree on every fixture, with the schema coming from
// different places, is the evidence that the reproduction is faithful.
//
// It compares the mutated object and the per-mutation cost. It does not compare
// `request`: the oracle's InProcessRequest fills a missing name, namespace and
// resource from the object the way a cluster does, and the playground
// deliberately does not invent them. No fixture below reads a field that
// differs, and the cluster tests are where request construction is checked.
func TestMAPPlaygroundMatchesUpstream(t *testing.T) {
	cases := map[string]mapParityCase{
		"applyconfig label":   {policy: "applyconfig label policy.yaml", object: "object.yaml"},
		"sidecar":             {policy: "sidecar policy.yaml", object: "sidecar object.yaml"},
		"variables":           {policy: "variables policy.yaml", object: "object.yaml"},
		"chained":             {policy: "chained policy.yaml", object: "object.yaml"},
		"jsonpatch ops":       {policy: "jsonpatch ops policy.yaml", object: "object.yaml"},
		"jsonpatch escapekey": {policy: "jsonpatch escapekey policy.yaml", object: "object.yaml"},
		"crd":                 {policy: "crd policy.yaml", object: "crd object.yaml"},
		"crd jsonpatch":       {policy: "crd jsonpatch policy.yaml", object: "crd object.yaml"},
		"yaml keys":           {policy: "yaml keys policy.yaml", object: "yaml keys object.yaml"},
		"v1alpha1":            {policy: "v1alpha1 policy.yaml", object: "object.yaml"},
		"v1beta1":             {policy: "v1beta1 policy.yaml", object: "object.yaml"},
		"context": {
			policy: "context policy.yaml", object: "object.yaml",
			oldObject: "context oldobject.yaml", request: "context request.yaml", rbac: "context rbac.yaml",
		},
		"serviceaccount": {
			policy: "serviceaccount policy.yaml", object: "object.yaml",
			request: "serviceaccount request.yaml", rbac: "serviceaccount rbac.yaml",
		},
		// An ApplyConfiguration naming a field the schema does not declare is
		// refused by the merge itself, so upstream fails here too -- and the
		// playground has to fail in the same place with the same reason.
		"patch typo": {policy: "patch typo policy.yaml", object: "object.yaml", wantFailures: 1},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			playground := runPlaygroundMutation(t, tc)
			upstream := runUpstreamMutation(t, tc)

			if len(playground.Mutations) != len(upstream.PerMutationError) {
				t.Fatalf("the playground ran %d mutations and upstream %d",
					len(playground.Mutations), len(upstream.PerMutationError))
			}

			failures := 0
			for i, mutation := range playground.Mutations {
				upstreamErr := upstream.PerMutationError[i]
				if mutation.IsError != (upstreamErr != nil) {
					t.Errorf("mutations[%d]: the playground %s and upstream %s\n  playground: %v\n  upstream:   %v",
						i, applied(!mutation.IsError), applied(upstreamErr == nil), errorText(mutation.Error), upstreamErr)
					continue
				}
				if mutation.IsError {
					failures++
					// The playground wraps some failures to say what a cluster
					// would do, so the reasons are compared by containment
					// rather than by equality.
					if !sharesReason(*mutation.Error, upstreamErr.Error()) {
						t.Errorf("mutations[%d] failed for different reasons\n  playground: %s\n  upstream:   %v",
							i, *mutation.Error, upstreamErr)
					}
					continue
				}
				if got, want := playgroundMutationCost(playground, i), upstream.Costs.Mutations[i]; int64(got) != want {
					t.Errorf("mutations[%d] cost %d here and %d upstream", i, got, want)
				}
			}
			if failures != tc.wantFailures {
				t.Errorf("%d mutations failed, want %d", failures, tc.wantFailures)
			}

			// The object is what the mode exists to produce, so it is compared
			// whole rather than field by field. Where nothing applied, the
			// playground reports no final object and upstream hands back its
			// input, so the input is what upstream's answer is held to.
			want := playground.FinalObject
			if want == "" {
				want = string(mustMarshalYAML(t, mustLoadFixtureObject(t, tc.object)))
			}
			if diff := yamlDiff(t, want, upstream.Object); diff != "" {
				t.Errorf("the mutated objects differ:\n%s", diff)
			}
		})
	}
}

func applied(ok bool) string {
	if ok {
		return "applied it"
	}
	return "refused it"
}

func errorText(err *string) string {
	if err == nil {
		return "<applied>"
	}
	return *err
}

// sharesReason reports whether two failure messages are about the same thing.
// structured-merge-diff's own wording is the part that has to match; what the
// playground adds around it is its own.
func sharesReason(playground, upstream string) bool {
	if strings.Contains(playground, upstream) || strings.Contains(upstream, playground) {
		return true
	}
	// Both quote the offending path, which is the load-bearing half.
	if i := strings.LastIndex(upstream, ": "); i >= 0 {
		return strings.Contains(playground, upstream[i+2:])
	}
	return false
}

// playgroundMutationCost is what the playground charged for one mutation: its
// expression plus the variables that mutation dereferenced. Upstream reports
// the two together as one budget delta, so the panel's split has to be undone
// before they can be compared.
func playgroundMutationCost(response k8s.EvalResponse, i int) uint64 {
	var cost uint64
	if response.Mutations[i].Cost != nil {
		cost = *response.Mutations[i].Cost
	}
	prefix := "mutations[" + itoa(i) + "]."
	for _, variable := range response.MutationVariables {
		if strings.HasPrefix(variable.Name, prefix) && variable.Cost != nil {
			cost += *variable.Cost
		}
	}
	return cost
}

func itoa(i int) string { return strconv.Itoa(i) }

func runPlaygroundMutation(t *testing.T, tc mapParityCase) k8s.EvalResponse {
	t.Helper()
	out, err := k8s.EvalMutatingAdmissionPolicy(
		readMap(t, tc.policy), readMap(t, tc.oldObject), readMap(t, tc.object),
		readMap(t, tc.namespace), readMap(t, tc.request), readMap(t, tc.rbac))
	if err != nil {
		t.Fatalf("the playground refused the fixture: %v", err)
	}
	response := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("decoding the playground's response: %v", err)
	}
	return response
}

func runUpstreamMutation(t *testing.T, tc mapParityCase) oracle.MutationResult {
	t.Helper()
	policy, err := oracle.LoadMutatingPolicy(oracle.MapFixture(tc.policy))
	if err != nil {
		t.Fatalf("loading the policy: %v", err)
	}
	request := oracle.InProcessRequest{}
	if tc.object != "" {
		if request.Object, err = oracle.LoadUnstructured(oracle.MapFixture(tc.object)); err != nil {
			t.Fatalf("loading the object: %v", err)
		}
	}
	if tc.oldObject != "" {
		if request.OldObject, err = oracle.LoadUnstructured(oracle.MapFixture(tc.oldObject)); err != nil {
			t.Fatalf("loading the old object: %v", err)
		}
	}
	if tc.request != "" {
		admissionRequest := &admissionv1.AdmissionRequest{}
		if err := yaml.UnmarshalStrict(readMap(t, tc.request), admissionRequest); err != nil {
			t.Fatalf("loading the request: %v", err)
		}
		if admissionRequest.Operation != "" {
			request.Operation = admission.Operation(admissionRequest.Operation)
		}
		if admissionRequest.Resource.Resource != "" {
			resource := schema.GroupVersionResource(admissionRequest.Resource)
			request.Resource = &resource
		}
		if admissionRequest.Kind.Kind != "" {
			kind := schema.GroupVersionKind(admissionRequest.Kind)
			request.Kind = &kind
		}
		request.Subresource = admissionRequest.SubResource
		request.ResourceName = admissionRequest.Name
		request.ResourceNamespace = admissionRequest.Namespace
		request.UserInfo = &user.DefaultInfo{
			Name:   admissionRequest.UserInfo.Username,
			UID:    admissionRequest.UserInfo.UID,
			Groups: admissionRequest.UserInfo.Groups,
			Extra:  extraValues(admissionRequest.UserInfo.Extra),
		}
	}
	if tc.rbac != "" {
		// The very authorizer the playground built, from the very same tab: what
		// is under test here is the mutation, not the RBAC resolution, which
		// has an oracle of its own.
		authorizer, err := k8s.NewRBACAuthorizer(readMap(t, tc.rbac))
		if err != nil {
			t.Fatalf("building the authorizer: %v", err)
		}
		request.Authorizer = authorizer
	}

	// The same choice the playground makes: the generated schema for a kind it
	// knows, the deduced converter for a custom resource. client-go's converter
	// refuses an unregistered kind outright, where a cluster would fetch the
	// CRD's own schema -- neither side of this comparison can do that, so both
	// fall back the same way and the fixture records what the fallback costs.
	typeConverter := oracle.StaticTypeConverter()
	if request.Object != nil {
		stub := &unstructured.Unstructured{}
		stub.SetGroupVersionKind(request.Object.GroupVersionKind())
		if _, err := typeConverter.ObjectToTyped(stub); err != nil {
			typeConverter = managedfields.NewDeducedTypeConverter()
		}
	}
	result, err := oracle.MutateInProcess(context.Background(), policy, request, typeConverter)
	if err != nil {
		t.Fatalf("upstream refused the fixture: %v", err)
	}
	return result
}

func readMap(t *testing.T, name string) []byte {
	t.Helper()
	if name == "" {
		return nil
	}
	data, err := os.ReadFile(oracle.MapFixture(name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return data
}

// yamlDiff compares the object the playground serialised against the one
// upstream produced, and returns "" when they are the same document.
func yamlDiff(t *testing.T, playground string, upstream *unstructured.Unstructured) string {
	t.Helper()
	if upstream == nil {
		if playground == "" {
			return ""
		}
		return "the playground mutated the object and upstream produced nothing:\n" + playground
	}
	want, err := yaml.Marshal(upstream)
	if err != nil {
		t.Fatalf("serialising upstream's object: %v", err)
	}
	if playground == string(want) {
		return ""
	}
	return "playground:\n" + playground + "\nupstream:\n" + string(want)
}

func mustLoadFixtureObject(t *testing.T, name string) *unstructured.Unstructured {
	t.Helper()
	object, err := oracle.LoadUnstructured(oracle.MapFixture(name))
	if err != nil {
		t.Fatalf("loading %s: %v", name, err)
	}
	return object
}

func mustMarshalYAML(t *testing.T, object any) []byte {
	t.Helper()
	out, err := yaml.Marshal(object)
	if err != nil {
		t.Fatalf("serialising: %v", err)
	}
	return out
}
