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

package k8s_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/undistro/cel-playground/k8s"
)

func mapTestfile(file string) string {
	return testfile("map/" + file)
}

// readMutationTestData reads the fixture files for one MutatingAdmissionPolicy
// test case. Empty names yield nil input, mirroring an empty editor tab in the
// playground UI.
func readMutationTestData(policy, oldObject, object, namespace, request, authorizer string) (policyData, oldObjectData, objectData, namespaceData, requestData, authorizerData []byte, err error) {
	policyData, err = testdata.ReadFile(mapTestfile(policy))
	if err == nil && oldObject != "" {
		oldObjectData, err = testdata.ReadFile(mapTestfile(oldObject))
	}
	if err == nil && object != "" {
		objectData, err = testdata.ReadFile(mapTestfile(object))
	}
	if err == nil && namespace != "" {
		namespaceData, err = testdata.ReadFile(mapTestfile(namespace))
	}
	if err == nil && request != "" {
		requestData, err = testdata.ReadFile(mapTestfile(request))
	}
	if err == nil && authorizer != "" {
		authorizerData, err = testdata.ReadFile(mapTestfile(authorizer))
	}
	return
}

// mutationExpectation describes the per-mutation assertions for a test case.
type mutationExpectation struct {
	patchType string
	isError   bool
	// errorContains, when non-empty, must be a substring of the mutation's
	// error message.
	errorContains string
	// contains lists substrings that must appear in this mutation's
	// mutatedObject YAML.
	contains []string
	// notContains lists substrings that must NOT appear in this mutation's
	// mutatedObject YAML.
	notContains []string
}

func TestMutationEval(t *testing.T) {
	tests := []struct {
		name       string
		policy     string
		oldObject  string
		object     string
		namespace  string
		request    string
		authorizer string

		// expectedVariables are the lazily evaluated spec.variables surfaced
		// for display, compared with reflect.DeepEqual when non-nil.
		expectedVariables []*k8s.EvalVariable
		// expectedMatchConditions is compared with reflect.DeepEqual when non-nil.
		expectedMatchConditions []*k8s.EvalResult
		// mutations describes the expected spec.mutations outcomes, in order.
		mutations []mutationExpectation
		// finalContains / finalNotContains assert on the final object YAML.
		finalContains    []string
		finalNotContains []string
		// failurePolicy / reinvocationPolicy are asserted when non-empty.
		failurePolicy      string
		reinvocationPolicy string
		// wantWarning, when non-empty, must be a substring of the single
		// reported warning. When empty, no warning may be reported at all.
		wantWarning string
		// wantNotSimulated lists substrings that must appear in the reported
		// caveats. Naming a policy field here also asserts that the caveat
		// survives whatever the matchConditions decided.
		wantNotSimulated []string
		// wantNoFinal asserts that no final object is reported at all, which is
		// the case when nothing was applied.
		wantNoFinal bool
		// wantDiff is true when the final object must differ from the input.
		wantDiff bool
		wantErr  bool
	}{{
		// 1. ApplyConfiguration adds a label.
		name:   "applyConfiguration adds a label",
		policy: "applyconfig label policy.yaml",
		object: "object.yaml",
		mutations: []mutationExpectation{{
			patchType: "ApplyConfiguration",
			contains:  []string{"environment: production", "app: nginx"},
		}},
		finalContains: []string{"environment: production"},
		wantDiff:      true,
	}, {
		// 2. ApplyConfiguration sidecar/initContainer injection (KEP canonical
		// example). initContainers is x-kubernetes-list-type=map keyed by name,
		// so the injected container must be MERGED alongside the existing
		// "setup" container, not replace it.
		name:   "applyConfiguration injects a sidecar initContainer",
		policy: "sidecar policy.yaml",
		object: "sidecar object.yaml",
		mutations: []mutationExpectation{{
			patchType: "ApplyConfiguration",
			contains:  []string{"mesh-proxy", "mesh-proxy:v1.0", "restartPolicy: Always"},
		}},
		finalContains: []string{
			"name: mesh-proxy",
			"name: setup", // pre-existing initContainer survives the merge
			"name: nginx",
		},
		wantDiff: true,
	}, {
		// 3. JSONPatch add + replace ops, applied in order.
		name:   "jsonPatch applies add and replace ops",
		policy: "jsonpatch ops policy.yaml",
		object: "object.yaml",
		mutations: []mutationExpectation{{
			patchType: "JSONPatch",
			contains:  []string{"team: platform", "replicas: 3"},
		}},
		finalContains:    []string{"team: platform", "replicas: 3"},
		finalNotContains: []string{"replicas: 1"},
		wantDiff:         true,
	}, {
		// 4. jsonpatch.escapeKey() on a label key containing '/'.
		name:   "jsonPatch escapeKey handles a slash in a label key",
		policy: "jsonpatch escapekey policy.yaml",
		object: "object.yaml",
		mutations: []mutationExpectation{{
			patchType: "JSONPatch",
			contains:  []string{"example.com/team: platform"},
		}},
		finalContains: []string{"example.com/team: platform"},
		wantDiff:      true,
	}, {
		// 5. Two mutations chained: the second sees the first's output.
		name:   "second mutation sees the first mutation's output",
		policy: "chained policy.yaml",
		object: "object.yaml",
		mutations: []mutationExpectation{{
			patchType:   "ApplyConfiguration",
			contains:    []string{"step: one"},
			notContains: []string{"step-seen-by-second"},
		}, {
			patchType: "ApplyConfiguration",
			contains:  []string{"step: one", "step-seen-by-second: one"},
		}},
		finalContains: []string{"step: one", "step-seen-by-second: one"},
		wantDiff:      true,
	}, {
		// 6. matchConditions evaluate to false: mutations are skipped entirely.
		name:   "matchConditions false skips all mutations",
		policy: "matchconditions false policy.yaml",
		object: "object.yaml",
		expectedMatchConditions: []*k8s.EvalResult{{
			Name:   strptr("is-production"),
			Result: false,
			Cost:   uint64ptr(5),
		}},
		mutations:   nil,
		wantNoFinal: true,
		wantDiff:    false,
	}, {
		// 7. spec.variables referenced from a mutation expression.
		name:   "spec.variables are usable inside a mutation expression",
		policy: "variables policy.yaml",
		object: "object.yaml",
		expectedVariables: []*k8s.EvalVariable{{
			Name:  "appName",
			Value: "nginx",
			Cost:  uint64ptr(7),
		}},
		mutations: []mutationExpectation{{
			patchType: "ApplyConfiguration",
			contains:  []string{"owning-app: nginx"},
		}},
		finalContains: []string{"owning-app: nginx"},
		wantDiff:      true,
	}, {
		// 8. An invalid mutation expression must surface as an IsError result,
		// not as a Go error and not as a panic. It also has to say what a
		// cluster would do with it, since the panel otherwise shows a failed
		// mutation beside whatever the others produced and looks like a partial
		// success.
		name:   "invalid mutation expression is reported as a result error",
		policy: "broken policy.yaml",
		object: "object.yaml",
		mutations: []mutationExpectation{{
			patchType:     "ApplyConfiguration",
			isError:       true,
			errorContains: "Object",
		}},
		wantWarning: "a cluster would have denied the request",
		wantDiff:    false,
	}, {
		// 9. oldObject / request / authorizer are reachable from a mutation.
		name:       "oldObject, request and authorizer are reachable in a mutation",
		policy:     "context policy.yaml",
		oldObject:  "context oldobject.yaml",
		object:     "object.yaml",
		request:    "context request.yaml",
		authorizer: "context authorizer.yaml",
		mutations: []mutationExpectation{{
			patchType: "ApplyConfiguration",
			contains: []string{
				"playground/operation: UPDATE",
				"playground/old-replicas: \"5\"",
				"playground/can-update: \"true\"",
			},
		}},
		finalContains: []string{"playground/operation: UPDATE"},
		wantDiff:      true,
	}, {
		// The v1beta1 (1.34) and v1alpha1 (1.32) schemas are structurally
		// identical to v1 and are normalized onto it, so they must evaluate the
		// same way. These two cases cover convertMAP's JSON round-trip.
		name:   "a v1beta1 policy evaluates like its v1 equivalent",
		policy: "v1beta1 policy.yaml",
		object: "object.yaml",
		mutations: []mutationExpectation{{
			patchType: "ApplyConfiguration",
			contains:  []string{"environment: production"},
		}},
		finalContains:      []string{"environment: production"},
		failurePolicy:      "Fail",
		reinvocationPolicy: "Never",
		wantDiff:           true,
	}, {
		name:   "a v1alpha1 policy evaluates like its v1 equivalent",
		policy: "v1alpha1 policy.yaml",
		object: "object.yaml",
		expectedVariables: []*k8s.EvalVariable{{
			Name:  "appName",
			Value: "nginx",
			Cost:  uint64ptr(7),
		}},
		mutations: []mutationExpectation{{
			patchType: "ApplyConfiguration",
			contains:  []string{"owning-app: nginx"},
		}},
		finalContains: []string{"owning-app: nginx"},
		wantDiff:      true,
	}, {
		// A custom resource has no embedded OpenAPI schema, so the playground
		// falls back to a schema-less converter that treats lists as atomic:
		// the injected part REPLACES the existing one rather than merging by
		// name. This is the degraded behavior the result panel warns about (the
		// warning built in mutatingadmissionpolicy.go), pinned here so it cannot
		// change silently.
		name:   "a custom resource falls back to atomic list merging",
		policy: "crd policy.yaml",
		object: "crd object.yaml",
		mutations: []mutationExpectation{{
			patchType:   "ApplyConfiguration",
			contains:    []string{"name: injected"},
			notContains: []string{"name: existing"},
		}},
		finalContains:    []string{"name: injected", "kind: Widget"},
		finalNotContains: []string{"name: existing"},
		wantWarning:      "No schema for example.com/v1",
		wantDiff:         true,
	}, {
		// The type converter is consulted only by ApplyConfiguration, so a
		// JSONPatch-only policy on the same custom resource is unaffected and
		// must not be warned about.
		name:   "a JSONPatch-only policy on a custom resource is not warned about",
		policy: "crd jsonpatch policy.yaml",
		object: "crd object.yaml",
		mutations: []mutationExpectation{{
			patchType: "JSONPatch",
			contains:  []string{"owner: platform", "name: existing"},
		}},
		finalContains: []string{"owner: platform"},
		wantDiff:      true,
	}, {
		// An erroring matchCondition must NOT run the mutations: on a cluster
		// failurePolicy=Fail rejects the request and Ignore skips the policy,
		// and neither produces a mutated object.
		name:        "an erroring matchCondition skips all mutations",
		policy:      "erroring matchcondition policy.yaml",
		object:      "object.yaml",
		mutations:   nil,
		wantNoFinal: true,
		wantDiff:    false,
	}, {
		// authorizer.serviceAccount() only swaps the request's user, so the
		// adapter has to recognize the service account by its username and
		// descend into the fixture's serviceAccounts section -- the same answer
		// the playground's own receiver types give.
		name:       "authorizer.serviceAccount resolves the serviceAccounts fixture",
		policy:     "serviceaccount policy.yaml",
		object:     "object.yaml",
		authorizer: "serviceaccount authorizer.yaml",
		mutations: []mutationExpectation{{
			patchType:   "ApplyConfiguration",
			contains:    []string{"playground/sa-reason: from-service-account"},
			notContains: []string{"top-level-authorizer"},
		}},
		wantDiff: true,
	}, {
		// A request made as a service account is an ordinary thing to put in the
		// Request tab, and must not redirect a check that never asked for one:
		// the fixture root describes what the requesting user can do. Reading the
		// serviceAccounts section here would answer from an account that is not
		// in the fixture at all, i.e. deny everything with nothing said about it.
		name:       "a service account request user still reads the fixture root",
		policy:     "root authorizer policy.yaml",
		object:     "object.yaml",
		request:    "root authorizer request.yaml",
		authorizer: "serviceaccount authorizer.yaml",
		mutations: []mutationExpectation{{
			patchType:   "ApplyConfiguration",
			contains:    []string{"playground/root-reason: top-level-authorizer"},
			notContains: []string{"from-service-account"},
		}},
		wantDiff: true,
	}, {
		// A field the schema does not declare, written by the mutation rather
		// than pasted by the user. The permissive schema merges it; a cluster
		// parses the patch strictly and refuses the whole mutation, so the only
		// thing standing between the user and a wrong answer is this warning.
		name:   "a mutation writing an undeclared field is warned about",
		policy: "patch typo policy.yaml",
		object: "object.yaml",
		mutations: []mutationExpectation{{
			patchType: "ApplyConfiguration",
			contains:  []string{"replicaz: 3"},
		}},
		wantWarning: "Mutation 1 writes fields the schema for apps/v1 Deployment does not declare: .spec.replicaz",
		wantDiff:    true,
	}, {
		// The lenient decoder the other modes share drops a misspelled policy
		// field, which for matchConditions means the gate silently disappears.
		// A cluster rejects the document, so the playground has to say what it
		// threw away.
		name:   "a dropped policy field is reported",
		policy: "unknown field policy.yaml",
		object: "object.yaml",
		mutations: []mutationExpectation{{
			patchType: "ApplyConfiguration",
			contains:  []string{"ran: \"yes\""},
		}},
		wantWarning: "dropped: matchConditons",
		wantDiff:    true,
	}, {
		// The object is decoded the way a real cluster does: kubectl converts
		// YAML to JSON with sigs.k8s.io/yaml (YAML 1.1), so the bare keys `on`,
		// `off`, `yes` and `n` become the boolean keys `true`/`false`. `on` and
		// `yes` both become `true` and `n` and `off` both become `false`, so
		// each pair collides and one annotation is silently dropped -- exactly
		// what the apiserver hands to admission control.
		name:   "YAML 1.1 boolean-looking keys coerce like a real cluster",
		policy: "yaml keys policy.yaml",
		object: "yaml keys object.yaml",
		mutations: []mutationExpectation{{
			patchType: "ApplyConfiguration",
			contains: []string{
				`"true": yes-value`,
				`"false": off-value`,
			},
			notContains: []string{`"n":`, `"on":`, `"yes":`, `"off":`},
		}},
		wantDiff: true,
	}, {
		// The Request tab drives request.name/namespace inside a mutation, the
		// same way it drives them inside a matchCondition. request.resource is
		// left blank here, so the resource is guessed from the kind.
		name:    "the Request tab drives request identity inside a mutation",
		policy:  "request identity policy.yaml",
		object:  "object.yaml",
		request: "request identity request.yaml",
		mutations: []mutationExpectation{{
			patchType: "ApplyConfiguration",
			contains: []string{
				"playground/req-name: name-from-request-tab",
				"playground/req-namespace: namespace-from-request-tab",
				"playground/req-resource: deployments",
			},
		}},
		failurePolicy:      "Ignore",
		reinvocationPolicy: "IfNeeded",
		wantDiff:           true,
	}, {
		// fieldSelector() narrows an authorizer check on a cluster, where RBAC can
		// grant a verb only for a given selector. Nothing reads the selector here
		// -- the Authorizer tab has no syntax for one -- so the check answers from
		// the un-narrowed entry, which is indistinguishable from a real answer:
		// `allowed()` is true and `reason()` is the un-narrowed entry's own. The
		// warning is the only thing that says so.
		name:       "a selector-narrowed authorizer check in a mutation is warned about",
		policy:     "selector mutation policy.yaml",
		object:     "object.yaml",
		authorizer: "selector authorizer.yaml",
		mutations: []mutationExpectation{{
			patchType: "ApplyConfiguration",
			contains: []string{
				"playground/narrowed: \"true\"",
				"playground/reason: un-narrowed",
			},
		}},
		wantWarning: "Mutation 1 narrows an authorizer check with fieldSelector() or labelSelector()",
		wantDiff:    true,
	}, {
		// The same expression in a matchCondition fails loudly instead: those go
		// through the playground's own receiver types, which implement no such
		// function. Two different wrong answers to one expression, so both halves
		// are pinned. An errored matchCondition counts as not matched, so no
		// mutation runs and no warning is added on top of the error.
		name:       "a selector-narrowed authorizer check in a matchCondition has no overload",
		policy:     "selector matchcondition policy.yaml",
		object:     "object.yaml",
		authorizer: "selector authorizer.yaml",
		expectedMatchConditions: []*k8s.EvalResult{{
			Error: strptr("unexpected error evaluating expression " +
				"authorizer.group('').resource('pods').fieldSelector('spec.nodeName=node-a')" +
				".check('list').allowed(): no such overload"),
			IsError: true,
		}},
		mutations:   nil,
		wantNoFinal: true,
		wantDiff:    false,
	}, {
		// The caveats describe the policy document, not the run, so a policy
		// switched off by its own matchConditions still reports them -- that is
		// exactly when a reader needs to be told params is bound to nothing.
		name:   "caveats are reported for a policy its own matchConditions switch off",
		policy: "gated paramkind policy.yaml",
		object: "object.yaml",
		expectedMatchConditions: []*k8s.EvalResult{{
			Name: strptr("never"),
			// A bare literal evaluates nothing, so it costs nothing.
			Result: false,
			Cost:   uint64ptr(0),
		}},
		wantNotSimulated: []string{"paramKind:", "matchConstraints:", "failurePolicy:", "API defaults:"},
		mutations:        nil,
		wantNoFinal:      true,
		wantDiff:         false,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, oldObject, object, namespace, request, authorizer, err := readMutationTestData(
				tt.policy, tt.oldObject, tt.object, tt.namespace, tt.request, tt.authorizer)
			if err != nil {
				t.Fatalf("failed to read test data: %v", err)
			}

			got, err := k8s.EvalMutatingAdmissionPolicy(policy, oldObject, object, namespace, request, authorizer)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EvalMutatingAdmissionPolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			var response k8s.EvalResponse
			if err := json.Unmarshal([]byte(got), &response); err != nil {
				t.Fatalf("failed to unmarshal response %q: %v", got, err)
			}

			if tt.expectedVariables != nil && !reflect.DeepEqual(response.MutationVariables, tt.expectedVariables) {
				t.Errorf("mutationVariables = %s, want %s",
					mustJSON(t, response.MutationVariables), mustJSON(t, tt.expectedVariables))
			}
			if tt.expectedMatchConditions != nil && !reflect.DeepEqual(response.MatchConditions, tt.expectedMatchConditions) {
				t.Errorf("matchConditions = %s, want %s",
					mustJSON(t, response.MatchConditions), mustJSON(t, tt.expectedMatchConditions))
			}

			if len(response.Mutations) != len(tt.mutations) {
				t.Fatalf("got %d mutations, want %d (mutations = %s)",
					len(response.Mutations), len(tt.mutations), mustJSON(t, response.Mutations))
			}
			for i, want := range tt.mutations {
				got := response.Mutations[i]
				if got.PatchType != want.patchType {
					t.Errorf("mutations[%d].patchType = %q, want %q", i, got.PatchType, want.patchType)
				}
				if got.IsError != want.isError {
					t.Errorf("mutations[%d].isError = %v, want %v (error = %v)", i, got.IsError, want.isError, derefStr(got.Error))
				}
				if want.errorContains != "" {
					if got.Error == nil {
						t.Errorf("mutations[%d].error = nil, want it to contain %q", i, want.errorContains)
					} else if !strings.Contains(*got.Error, want.errorContains) {
						t.Errorf("mutations[%d].error = %q, want it to contain %q", i, *got.Error, want.errorContains)
					}
				}
				for _, want := range want.contains {
					if !strings.Contains(got.MutatedObject, want) {
						t.Errorf("mutations[%d].mutatedObject does not contain %q:\n%s", i, want, got.MutatedObject)
					}
				}
				for _, notWant := range want.notContains {
					if strings.Contains(got.MutatedObject, notWant) {
						t.Errorf("mutations[%d].mutatedObject unexpectedly contains %q:\n%s", i, notWant, got.MutatedObject)
					}
				}
			}

			for _, want := range tt.finalContains {
				if !strings.Contains(response.FinalObject, want) {
					t.Errorf("finalObject does not contain %q:\n%s", want, response.FinalObject)
				}
			}
			for _, notWant := range tt.finalNotContains {
				if strings.Contains(response.FinalObject, notWant) {
					t.Errorf("finalObject unexpectedly contains %q:\n%s", notWant, response.FinalObject)
				}
			}

			switch {
			case tt.wantWarning == "":
				if len(response.Warnings) != 0 {
					t.Errorf("got warnings %q, want none", response.Warnings)
				}
			case len(response.Warnings) != 1:
				t.Errorf("got %d warnings, want 1 containing %q: %q",
					len(response.Warnings), tt.wantWarning, response.Warnings)
			case !strings.Contains(response.Warnings[0], tt.wantWarning):
				t.Errorf("warning = %q, want it to contain %q", response.Warnings[0], tt.wantWarning)
			}

			for _, want := range tt.wantNotSimulated {
				if !strings.Contains(response.NotSimulated, want) {
					t.Errorf("notSimulated = %q, want it to mention %q", response.NotSimulated, want)
				}
			}

			if tt.wantNoFinal && response.FinalObject != "" {
				t.Errorf("finalObject = %q, want it to be absent", response.FinalObject)
			}

			if tt.failurePolicy != "" && response.FailurePolicy != tt.failurePolicy {
				t.Errorf("failurePolicy = %q, want %q", response.FailurePolicy, tt.failurePolicy)
			}
			if tt.reinvocationPolicy != "" && response.ReinvocationPolicy != tt.reinvocationPolicy {
				t.Errorf("reinvocationPolicy = %q, want %q", response.ReinvocationPolicy, tt.reinvocationPolicy)
			}

			if gotDiff := response.Diff != ""; gotDiff != tt.wantDiff {
				t.Errorf("diff present = %v, want %v; diff =\n%s", gotDiff, tt.wantDiff, response.Diff)
			}

			if response.Cost == nil {
				t.Error("cost is nil, want a total cost")
			}
		})
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("failed to marshal %v: %v", v, err)
	}
	return string(out)
}

func derefStr(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// TestMutationEvalWithoutAnObject checks that an unusable Object tab is
// reported against each mutation rather than failing the whole evaluation,
// so the matchCondition results the user did get are still rendered.
func TestMutationEvalWithoutAnObject(t *testing.T) {
	tests := []struct {
		name          string
		object        string
		errorContains string
	}{{
		name:          "empty object tab",
		object:        "",
		errorContains: "an object is required",
	}, {
		name:          "object without apiVersion or kind",
		object:        "metadata:\n  name: nameless\n",
		errorContains: "must set apiVersion and kind",
	}}

	policy, err := testdata.ReadFile(mapTestfile("applyconfig label policy.yaml"))
	if err != nil {
		t.Fatalf("failed to read test data: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := k8s.EvalMutatingAdmissionPolicy(policy, nil, []byte(tt.object), nil, nil, nil)
			if err != nil {
				t.Fatalf("EvalMutatingAdmissionPolicy() error = %v, want the error reported per mutation", err)
			}
			var response k8s.EvalResponse
			if err := json.Unmarshal([]byte(got), &response); err != nil {
				t.Fatalf("failed to unmarshal response %q: %v", got, err)
			}
			if len(response.Mutations) != 1 {
				t.Fatalf("got %d mutations, want 1", len(response.Mutations))
			}
			mutation := response.Mutations[0]
			if !mutation.IsError {
				t.Error("mutation is not marked as an error")
			}
			if mutation.Error == nil || !strings.Contains(*mutation.Error, tt.errorContains) {
				t.Errorf("mutation error = %v, want it to contain %q", derefStr(mutation.Error), tt.errorContains)
			}
			if mutation.PatchType != "ApplyConfiguration" {
				t.Errorf("patchType = %q, want ApplyConfiguration", mutation.PatchType)
			}
			if response.FinalObject != "" {
				t.Errorf("finalObject = %q, want empty", response.FinalObject)
			}
		})
	}
}

// TestMergeByKeyOnNewlyCoveredGroupVersion is the regression guard for the
// behaviour this mode exists to reproduce: a cluster merges an
// x-kubernetes-list-type=map list by its key, so the playground must too.
//
// admissionregistration.k8s.io/v1 is deliberately chosen. Its
// ValidatingWebhookConfiguration.webhooks list is keyed by name, and the
// group-version had no schema at all while the mode read OpenAPI specs from
// client-go's test fixtures -- so this exact policy used to delete
// policy-b.example.com and report a missing-schema warning. Any regression that
// narrows schema coverage brings that silent deletion back.
func TestMergeByKeyOnNewlyCoveredGroupVersion(t *testing.T) {
	policy := []byte(`apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata:
  name: set-failure-policy-on-one-webhook
spec:
  mutations:
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{webhooks: [Object.webhooks{name: "policy-a.example.com", failurePolicy: "Fail"}]}
`)
	object := []byte(`apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: existing-config
webhooks:
- name: policy-a.example.com
  sideEffects: None
  admissionReviewVersions: ["v1"]
  clientConfig:
    url: https://a.example.com/validate
- name: policy-b.example.com
  sideEffects: None
  admissionReviewVersions: ["v1"]
  clientConfig:
    url: https://b.example.com/validate
`)

	got, err := k8s.EvalMutatingAdmissionPolicy(policy, nil, object, nil, nil, nil)
	if err != nil {
		t.Fatalf("EvalMutatingAdmissionPolicy() error = %v", err)
	}
	var response k8s.EvalResponse
	if err := json.Unmarshal([]byte(got), &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if len(response.Warnings) != 0 {
		t.Errorf("got warnings %q, want none -- the group-version should be schema-backed",
			response.Warnings)
	}
	for _, want := range []string{
		"policy-a.example.com", // named by the patch
		"policy-b.example.com", // untouched, and must survive the merge
		"failurePolicy: Fail",  // the patch was actually applied
		"https://b.example.com/validate",
	} {
		if !strings.Contains(response.FinalObject, want) {
			t.Errorf("finalObject does not contain %q:\n%s", want, response.FinalObject)
		}
	}
}

// The display-side variables are evaluated whether or not a mutation gets far
// enough to charge for them, so a policy whose mutation never evaluates must
// still report what that evaluation cost. Reporting zero for work the panel
// shows is the failure this pins.
func TestCostCoversVariablesWhenNoMutationEvaluated(t *testing.T) {
	policy := []byte(`apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata:
  name: cost
spec:
  variables:
  - name: appName
    expression: "object.metadata.name"
  mutations:
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: "1 + 1"
`)
	object := []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: nginx\nspec:\n  replicas: 1\n")

	out, err := k8s.EvalMutatingAdmissionPolicy(policy, nil, object, nil, nil, nil)
	if err != nil {
		t.Fatalf("EvalMutatingAdmissionPolicy() error = %v", err)
	}
	var response k8s.EvalResponse
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(response.Mutations) != 1 || !response.Mutations[0].IsError {
		t.Fatalf("expected one errored mutation, got %+v", response.Mutations)
	}
	if len(response.MutationVariables) != 1 || response.MutationVariables[0].Cost == nil {
		t.Fatalf("expected one variable with a cost, got %+v", response.MutationVariables)
	}
	variableCost := *response.MutationVariables[0].Cost
	if response.Cost == nil {
		t.Fatal("total cost is absent")
	}
	if *response.Cost != variableCost {
		t.Errorf("total cost = %d, want %d (the variable the panel charges for)", *response.Cost, variableCost)
	}
}
