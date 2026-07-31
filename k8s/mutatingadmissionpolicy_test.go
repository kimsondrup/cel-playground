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
				// The Object tab holds a Deployment; only the Request tab says
				// Scale, so this is the half that a wrong VersionedKind breaks.
				"playground/req-kind: Scale",
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
		// This policy leaves failurePolicy unset, which means Fail -- the
		// setting whose effect the playground cannot reproduce -- so the caveat
		// has to be there for it as much as for a policy that spells it out.
		wantNotSimulated: []string{"failurePolicy: Fail asks the apiserver to deny the request"},
		wantDiff:         true,
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
	}, {
		// Only the mutation that wrote the undeclared field is named. The
		// second one inherits it in its input and must not be blamed for it.
		name:   "an undeclared field is blamed on the mutation that wrote it",
		policy: "chained typo policy.yaml",
		object: "object.yaml",
		mutations: []mutationExpectation{{
			patchType: "JSONPatch",
			contains:  []string{"replicaz: 3"},
		}, {
			patchType: "ApplyConfiguration",
			contains:  []string{"second: ran", "replicaz: 3"},
		}},
		wantWarning:   "Mutation 1",
		finalContains: []string{"second: ran"},
		wantDiff:      true,
	}, {
		// A cluster decodes a patched object into its typed form, strictly, and
		// refuses a string where the schema declares an integer. Everything
		// here stays unstructured, so the patch applies cleanly and the warning
		// is the only thing that says a cluster would have refused it.
		name:   "a mutation writing a value the schema will not accept",
		policy: "quoted number policy.yaml",
		object: "object.yaml",
		mutations: []mutationExpectation{{
			patchType: "JSONPatch",
			contains:  []string{`replicas: "10"`},
		}},
		wantWarning: "Mutation 1 writes a value the schema for apps/v1 Deployment does not " +
			"accept: .spec.replicas: expected numeric (int or float), got string",
		wantDiff: true,
	}, {
		// The object arrived with the bad value, so it is reported once against
		// the object. The mutation never touched it and must not be named for
		// it -- the table asserts a single warning.
		name:   "a value the object arrived with is not blamed on a mutation",
		policy: "jsonpatch label policy.yaml",
		object: "rejected value object.yaml",
		mutations: []mutationExpectation{{
			patchType: "JSONPatch",
			contains:  []string{"environment: production"},
		}},
		wantWarning: "The schema for apps/v1 Deployment does not accept: .spec.replicas",
		wantDiff:    true,
	}, {
		// The object arrived with the undeclared field, so it is reported once
		// against the object. A mutation that never touched it must not be
		// blamed for it a second time -- the table asserts a single warning.
		name:   "an undeclared field the object arrived with is not blamed on a mutation",
		policy: "applyconfig label policy.yaml",
		object: "undeclared field object.yaml",
		mutations: []mutationExpectation{{
			patchType: "ApplyConfiguration",
			contains:  []string{"environment: production", "replicazz: 2"},
		}},
		wantWarning: "The schema for apps/v1 Deployment does not declare: .spec.replicazz",
		wantDiff:    true,
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
      # Reads the variable, so the variable is evaluated for display, and is
      # not an Object, so the mutation itself never gets as far as running.
      expression: "variables.appName"
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

// TestTabWarningsNameTheDivergence covers the two environments reading one tab
// differently. The matchConditions are given the tabs as typed; the mutations
// are given an admission attribute record, which has no blanks to offer and
// takes a name, a namespace and a resource from the object instead. An
// expression reading one of those answers differently on each side, and the
// warning is the only thing that says so -- especially when the matchCondition
// is what closed the gate, so there is no mutation and no diff to look at.
// TestOutcomeStatesWhatHappened covers the endings the panel otherwise conveys
// by leaving a section out. A gate that closed produces no mutation, no diff
// and no final object, and "why did nothing happen" is the question the mode
// exists to answer.
func TestOutcomeStatesWhatHappened(t *testing.T) {
	object := []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: nginx\n" +
		"  labels:\n    app: nginx\nspec:\n  replicas: 1\n")
	policy := func(failurePolicy, matchCondition, mutation string) []byte {
		return []byte(`apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata:
  name: outcome
spec:
  failurePolicy: ` + failurePolicy + `
  reinvocationPolicy: Never
  matchConditions:
  - name: gate
    expression: "` + matchCondition + `"
  mutations:
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        ` + mutation + "\n")
	}
	const addsALabel = `Object{metadata: Object.metadata{labels: {"ran": "yes"}}}`

	tests := []struct {
		name           string
		failurePolicy  string
		matchCondition string
		mutation       string
		want           string
	}{{
		name:           "the matchConditions did not match",
		failurePolicy:  "Ignore",
		matchCondition: "false",
		mutation:       addsALabel,
		want:           "The matchConditions did not match, so no mutation ran",
	}, {
		// A cluster does not skip the policy here, it rejects the request.
		name:           "a matchCondition errored under the default failurePolicy",
		failurePolicy:  "Fail",
		matchCondition: "object.metadata.labels['absent'] == 'x'",
		mutation:       addsALabel,
		want:           "failurePolicy is Fail, so a cluster would reject the request outright",
	}, {
		name:           "a matchCondition errored under failurePolicy Ignore",
		failurePolicy:  "Ignore",
		matchCondition: "object.metadata.labels['absent'] == 'x'",
		mutation:       addsALabel,
		want:           "failurePolicy is Ignore, so a cluster would admit the request",
	}, {
		// Setting a label to the value it already has. Without this the panel
		// shows a successful mutation and simply omits the diff.
		name:           "a mutation that changed nothing",
		failurePolicy:  "Ignore",
		matchCondition: "true",
		mutation:       `Object{metadata: Object.metadata{labels: {"app": "nginx"}}}`,
		want:           "The mutations ran and left the object unchanged.",
	}, {
		// The diff says what happened, so there is nothing to add.
		name:           "a mutation that changed something",
		failurePolicy:  "Ignore",
		matchCondition: "true",
		mutation:       addsALabel,
		want:           "",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := k8s.EvalMutatingAdmissionPolicy(
				policy(tt.failurePolicy, tt.matchCondition, tt.mutation), nil, object, nil, nil, nil)
			if err != nil {
				t.Fatalf("EvalMutatingAdmissionPolicy() error = %v", err)
			}
			var response k8s.EvalResponse
			if err := json.Unmarshal([]byte(out), &response); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			switch {
			case tt.want == "" && response.Outcome != "":
				t.Errorf("outcome = %q, want none -- the diff already says what happened",
					response.Outcome)
			case tt.want != "" && !strings.Contains(response.Outcome, tt.want):
				t.Errorf("outcome = %q, want it to contain %q", response.Outcome, tt.want)
			}
		})
	}
}

func TestTabWarningsNameTheDivergence(t *testing.T) {
	object := []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: nginx\n  namespace: prod\nspec:\n  replicas: 1\n")
	// A matchCondition that reads nothing, so a case naming only a mutation
	// expression is testing the mutation side alone.
	const inertMatchCondition = "true"
	policy := func(matchCondition, mutation string) []byte {
		if matchCondition == "" {
			matchCondition = inertMatchCondition
		}
		if mutation == "" {
			mutation = `Object{metadata: Object.metadata{labels: {"ran": "yes"}}}`
		}
		return []byte(`apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata:
  name: tabs
spec:
  failurePolicy: Ignore
  reinvocationPolicy: Never
  matchConditions:
  - name: gate
    expression: "` + matchCondition + `"
  mutations:
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        ` + mutation + "\n")
	}

	tests := []struct {
		name           string
		matchCondition string
		// mutation overrides the default mutation expression, for the cases
		// where the mutation is the only thing reading a tab.
		mutation  string
		operation string
		// request overrides the Request tab, which is otherwise left out
		// entirely -- the case the warning is mostly about.
		request   []byte
		namespace []byte
		want      string
		// notWant must not appear in the warning.
		notWant string
	}{{
		// The gate closes because request.name is empty on this side while the
		// mutation would have read "nginx".
		name:           "a matchCondition reading the request tab",
		matchCondition: "request.name == 'nginx'",
		want:           "The Request tab leaves",
	}, {
		name:           "a matchCondition reading an authorizer check keyed on the request",
		matchCondition: "authorizer.requestResource.check('update').allowed()",
		want:           "The Request tab leaves",
	}, {
		// Nothing reads the request, so nothing could have observed the
		// difference and the warning would be noise.
		name:           "a matchCondition reading only the object",
		matchCondition: "object.metadata.name == 'nginx'",
		want:           "",
	}, {
		name:           "a matchCondition reading a nameless namespace tab",
		matchCondition: "namespaceObject.metadata.name == 'prod'",
		namespace:      []byte(""),
		want:           "The Namespace tab names no namespace",
	}, {
		// The mutation is the only thing reading the tab, and it is the case
		// with no other output to reason from: the mutation fails, and without
		// this the only thing on screen says a cluster would have denied the
		// request -- for a policy that works on any real cluster.
		name:      "only a mutation reads the namespace tab",
		mutation:  `Object{metadata: Object.metadata{annotations: {"ns": namespaceObject.metadata.name}}}`,
		namespace: []byte(""),
		want:      "The Namespace tab names no namespace",
	}, {
		name:     "only a mutation reads the request tab",
		mutation: `Object{metadata: Object.metadata{annotations: {"n": request.name}}}`,
		want:     "The Request tab leaves",
	}, {
		// Set, but not an operation a cluster sends. Worse than leaving it
		// blank, because the tab side reads it back verbatim.
		name:           "an operation no cluster sends",
		matchCondition: "request.operation == 'PATCH'",
		operation:      "PATCH",
		want:           "which is not one of CREATE, UPDATE, DELETE, CONNECT",
	}, {
		// Only the resource is missing, so only the resource may be explained.
		// A fixed list of substitutions would tell the reader their mutation
		// saw CREATE when the tab plainly says UPDATE.
		name:     "a request tab missing only the resource",
		mutation: `Object{metadata: Object.metadata{annotations: {"n": request.name}}}`,
		request: []byte("name: \"nginx\"\nnamespace: \"prod\"\noperation: \"UPDATE\"\n" +
			"kind:\n  group: \"apps\"\n  version: \"v1\"\n  kind: \"Deployment\"\n"),
		want:    "leaves resource unset",
		notWant: "CREATE",
	}, {
		// resources.requests is not the Request tab. A policy looking at
		// container resources is common enough that matching it would put the
		// warning on screen for most of them.
		name:           "a matchCondition reading container resource requests",
		matchCondition: "object.spec.template.spec.containers.all(c, has(c.resources))",
		want:           "",
	}, {
		// Named, so the field the expression reads is set on both sides.
		name:           "a matchCondition reading a named namespace tab",
		matchCondition: "namespaceObject.metadata.name == 'prod'",
		namespace:      []byte("metadata:\n  name: prod\n"),
		want:           "",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The Request tab is left out entirely unless the case sets an
			// operation, which is the case the warning is about.
			request := tt.request
			if tt.operation != "" {
				request = []byte("operation: \"" + tt.operation + "\"\n")
			}
			out, err := k8s.EvalMutatingAdmissionPolicy(
				policy(tt.matchCondition, tt.mutation), nil, object, tt.namespace, request, nil)
			if err != nil {
				t.Fatalf("EvalMutatingAdmissionPolicy() error = %v", err)
			}
			var response k8s.EvalResponse
			if err := json.Unmarshal([]byte(out), &response); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			var got string
			for _, warning := range response.Warnings {
				if strings.Contains(warning, " tab ") || strings.Contains(warning, " tab is") {
					got = warning
				}
			}
			switch {
			case tt.want == "" && got != "":
				t.Errorf("got warning %q, want none -- no expression reads the tab", got)
			case tt.want != "" && !strings.Contains(got, tt.want):
				t.Errorf("warning = %q, want it to contain %q", got, tt.want)
			case tt.notWant != "" && strings.Contains(got, tt.notWant):
				t.Errorf("warning = %q, want it not to mention %q", got, tt.notWant)
			}
		})
	}
}

// TestUnreferencedVariableIsNotEvaluated pins that a variable no expression
// reads is left alone. A cluster binds spec.variables lazily and never
// evaluates one nothing asks for, so it cannot fail there; evaluating it here
// would report an error against a variable that a cluster would not have run.
func TestUnreferencedVariableIsNotEvaluated(t *testing.T) {
	policy := []byte(`apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata:
  name: unreferenced
spec:
  variables:
  - name: used
    expression: "'production'"
  - name: unused
    expression: "1 / 0"
  mutations:
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{metadata: Object.metadata{labels: {"environment": variables.used}}}
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

	if len(response.MutationVariables) != 1 {
		t.Fatalf("got %d variables, want only the one the mutation reads: %+v",
			len(response.MutationVariables), response.MutationVariables)
	}
	if got := response.MutationVariables[0]; got.Name != "used" || got.IsError {
		t.Errorf("variable = %+v, want used, evaluated without error", got)
	}
	if len(response.Mutations) != 1 || response.Mutations[0].IsError {
		t.Fatalf("expected the mutation to run, got %+v", response.Mutations)
	}
}

// TestCostIncludesAVariableAMatchConditionRead pins that the total covers a
// variable this environment evaluated on its own. A mutation is charged for
// its own evaluation of the variables it reads, so those are not counted
// twice, but nothing else accounts for one a matchCondition pulled in.
//
// Kubernetes does not allow spec.variables in matchConditions at all -- they
// are evaluated before the rest of the policy -- so a cluster would reject this
// document. The playground evaluates it anyway, and the panel displays the
// variable with a cost, so the total has to include it.
func TestCostIncludesAVariableAMatchConditionRead(t *testing.T) {
	policy := []byte(`apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata:
  name: matchcondition-variable
spec:
  variables:
  - name: appName
    expression: "object.metadata.name"
  matchConditions:
  - name: named-nginx
    expression: "variables.appName == 'nginx'"
  mutations:
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{metadata: Object.metadata{labels: {"ran": "yes"}}}
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

	if len(response.MutationVariables) != 1 || response.MutationVariables[0].Cost == nil {
		t.Fatalf("expected one variable with a cost, got %+v", response.MutationVariables)
	}
	var want uint64
	for _, result := range response.MatchConditions {
		if result.Cost != nil {
			want += *result.Cost
		}
	}
	want += *response.MutationVariables[0].Cost
	for _, mutation := range response.Mutations {
		if mutation.Cost != nil {
			want += *mutation.Cost
		}
	}
	if response.Cost == nil {
		t.Fatal("total cost is absent")
	}
	if *response.Cost != want {
		t.Errorf("total cost = %d, want %d -- the sum of every cost the panel shows",
			*response.Cost, want)
	}
}
