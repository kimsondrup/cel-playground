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

package k8s_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/undistro/cel-playground/k8s"
)

func evalMutation(t *testing.T, policy, object, request, rbac string) k8s.EvalResponse {
	t.Helper()
	out, err := k8s.EvalMutatingAdmissionPolicy(
		readMapFile(t, policy), nil, readMapFile(t, object), nil,
		readMapFile(t, request), readMapFile(t, rbac))
	if err != nil {
		t.Fatalf("EvalMutatingAdmissionPolicy() error: %v", err)
	}
	response := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	return response
}

// A JSON Patch can grow a document without spending CEL cost: `copy` duplicates
// a subtree for a handful of cost units whatever its size, so twelve of them
// turn a 400-byte object into megabytes at a cost of 490 out of ten million.
// The cost budget does not bound output size, and both of these bounds exist
// because of a reproduced attack of exactly that shape.
//
// The object is a custom resource on purpose. A built-in would be read back
// against its schema and refused for the undeclared fields the copies create,
// which is a different bound entirely and would hide these two.
func TestMutationBoundsTheObjectItProduces(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		want   string
	}{{
		// Bounded by the playground: nothing upstream limits what a policy
		// accumulates across mutations, and an object this size is one no
		// cluster would have carried in a request body.
		name:   "an object grown past what a cluster would store is not applied",
		policy: "copy grows the object policy.yaml",
		want:   "past the 1048576 the playground will work with",
	}, {
		// Bounded by the patch library, armed from the apiserver's own
		// JSONPatchMaxCopyBytes. Without the init() that arms it the default is
		// unlimited, because the playground never builds a GenericAPIServer.
		name:   "a patch that copies past the accumulated-copy limit is refused",
		policy: "copy exceeds the patch limit policy.yaml",
		want:   "exceeding the limit 3145728",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := k8s.EvalMutatingAdmissionPolicy(
				readMapFile(t, tt.policy), nil, readMapFile(t, "bomb object.yaml"), nil, nil, nil)
			if err != nil {
				t.Fatalf("EvalMutatingAdmissionPolicy() error: %v", err)
			}
			// The response is what crosses into the browser, so its size is the
			// thing being bounded. A megabyte here is the attack succeeding.
			if len(out) > 4096 {
				t.Errorf("the response is %d bytes; the mutated object was not withheld", len(out))
			}
			response := k8s.EvalResponse{}
			if err := json.Unmarshal([]byte(out), &response); err != nil {
				t.Fatalf("json.Unmarshal() error: %v", err)
			}
			if len(response.Mutations) != 1 {
				t.Fatalf("got %d mutations, want 1", len(response.Mutations))
			}
			mutation := response.Mutations[0]
			if !mutation.IsError || mutation.Error == nil {
				t.Fatalf("the mutation was applied, want it refused")
			}
			if !strings.Contains(*mutation.Error, tt.want) {
				t.Errorf("error = %q, want it to mention %q", *mutation.Error, tt.want)
			}
			if mutation.MutatedObject != "" {
				t.Errorf("the refused object was reported anyway (%d bytes)", len(mutation.MutatedObject))
			}
			if response.FinalObject != "" {
				t.Errorf("the refused object became the final object (%d bytes)", len(response.FinalObject))
			}
		})
	}
}

// notSimulated is what stops a policy the playground only half-runs from
// reporting a confident result. Each line is a field the mode parses and does
// not act on, and each is reported whatever the matchConditions did -- a policy
// gated off by its own matchConditions is exactly when the reader has least
// else to go on.
func TestMutationReportsWhatItDoesNotSimulate(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		want   []string
		absent []string
	}{{
		name:   "matchConstraints and defaulting",
		policy: "applyconfig label policy.yaml",
		want:   []string{"matchConstraints:", "API defaults:"},
		absent: []string{"paramKind:", "reinvocationPolicy:"},
	}, {
		name:   "paramKind, even when the policy never fires",
		policy: "gated paramkind policy.yaml",
		want:   []string{"matchConstraints:", "paramKind:", "API defaults:"},
	}, {
		name:   "a policy with no matchConstraints does not claim to ignore them",
		policy: "crd jsonpatch policy.yaml",
		want:   []string{"API defaults:"},
		absent: []string{"matchConstraints:", "paramKind:"},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := evalMutation(t, tt.policy, "object.yaml", "", "")
			for _, want := range tt.want {
				if !strings.Contains(response.NotSimulated, want) {
					t.Errorf("notSimulated does not mention %q:\n%s", want, response.NotSimulated)
				}
			}
			for _, absent := range tt.absent {
				if strings.Contains(response.NotSimulated, absent) {
					t.Errorf("notSimulated mentions %q, which this policy does not use:\n%s", absent, response.NotSimulated)
				}
			}
		})
	}
}

// reinvocationPolicy: IfNeeded asks the apiserver for another pass once some
// other plugin has mutated the object. There is no other plugin here, so each
// mutation runs once and the panel has to say so.
func TestMutationReportsReinvocation(t *testing.T) {
	policy := strings.Replace(string(readMapFile(t, "applyconfig label policy.yaml")),
		"reinvocationPolicy: Never", "reinvocationPolicy: IfNeeded", 1)
	out, err := k8s.EvalMutatingAdmissionPolicy([]byte(policy), nil, readMapFile(t, "object.yaml"), nil, nil, nil)
	if err != nil {
		t.Fatalf("EvalMutatingAdmissionPolicy() error: %v", err)
	}
	response := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if !strings.Contains(response.NotSimulated, "reinvocationPolicy:") {
		t.Errorf("notSimulated does not mention reinvocationPolicy:\n%s", response.NotSimulated)
	}
}

// A mutation names its patch type and carries a body matching it. A policy that
// disagrees with itself is refused by the registry, so it never reaches a
// cluster and the mutation has nothing to run.
func TestMutationRejectsAMalformedPatchType(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		want   string
		reject bool
	}{{
		name: "ApplyConfiguration with no applyConfiguration",
		body: "  - patchType: ApplyConfiguration\n",
		want: "patchType is ApplyConfiguration, so applyConfiguration.expression must be set",
	}, {
		name: "JSONPatch with no jsonPatch",
		body: "  - patchType: JSONPatch\n",
		want: "patchType is JSONPatch, so jsonPatch.expression must be set",
	}, {
		name: "no patchType at all",
		body: "  - jsonPatch:\n      expression: \"[]\"\n",
		want: "patchType is not set; expected ApplyConfiguration or JSONPatch",
	}, {
		name: "a patch type that does not exist",
		body: "  - patchType: StrategicMerge\n    jsonPatch:\n      expression: \"[]\"\n",
		want: `unsupported patchType "StrategicMerge"`,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := "apiVersion: admissionregistration.k8s.io/v1\nkind: MutatingAdmissionPolicy\nmetadata:\n  name: malformed\nspec:\n  failurePolicy: Fail\n  reinvocationPolicy: Never\n  mutations:\n" + tt.body
			out, err := k8s.EvalMutatingAdmissionPolicy([]byte(policy), nil, readMapFile(t, "object.yaml"), nil, nil, nil)
			if err != nil {
				t.Fatalf("EvalMutatingAdmissionPolicy() error: %v", err)
			}
			response := k8s.EvalResponse{}
			if err := json.Unmarshal([]byte(out), &response); err != nil {
				t.Fatalf("json.Unmarshal() error: %v", err)
			}
			if len(response.Mutations) != 1 {
				t.Fatalf("got %d mutations, want 1: %s", len(response.Mutations), out)
			}
			if !response.Mutations[0].IsError {
				t.Fatalf("the mutation ran, want it refused")
			}
			if got := *response.Mutations[0].Error; !strings.Contains(got, tt.want) {
				t.Errorf("error = %q, want it to mention %q", got, tt.want)
			}
		})
	}
}

// Each mutation is patched on its own with a whole cost budget, the way the
// dispatcher hands celconfig.RuntimeCELCostBudget to every Patch call. Two
// mutations that each stay inside it do not add up to an overrun, however much
// they cost together.
func TestMutationBudgetsArePerMutation(t *testing.T) {
	// An authorizer check costs ~350,000, and celconfig.PerCallLimit caps any
	// one expression at 1,000,000 -- so the only way to spend a budget is
	// across variables. Eight of two checks each is ~5.6 million per mutation:
	// inside a budget of its own, and over ten million once two mutations share
	// one. Sharing and not sharing are therefore told apart by whether anything
	// is reported at all, not by a margin.
	const variables = 8
	check := func(verb string) string {
		return fmt.Sprintf("string(authorizer.group('apps').resource('deployments').check('%s').allowed())", verb)
	}
	declarations, reads := "", make([]string, 0, variables)
	for i := range variables {
		declarations += fmt.Sprintf("  - name: v%d\n    expression: \"%s + %s\"\n",
			i, check(fmt.Sprintf("a%d", i)), check(fmt.Sprintf("b%d", i)))
		reads = append(reads, fmt.Sprintf("%q: variables.v%d", fmt.Sprintf("v%d", i), i))
	}
	mutation := "  - patchType: ApplyConfiguration\n    applyConfiguration:\n      expression: >\n        Object{metadata: Object.metadata{annotations: {" + strings.Join(reads, ", ") + "}}}\n"
	policy := "apiVersion: admissionregistration.k8s.io/v1\nkind: MutatingAdmissionPolicy\nmetadata:\n  name: budgets\nspec:\n  failurePolicy: Fail\n  reinvocationPolicy: Never\n  variables:\n" + declarations + "  mutations:\n" + mutation + mutation

	out, err := k8s.EvalMutatingAdmissionPolicy([]byte(policy), nil, readMapFile(t, "object.yaml"), nil, nil, nil)
	if err != nil {
		t.Fatalf("EvalMutatingAdmissionPolicy() error: %v", err)
	}
	response := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if len(response.Mutations) != 2 {
		t.Fatalf("got %d mutations, want 2", len(response.Mutations))
	}
	for i, m := range response.Mutations {
		if m.IsError {
			t.Fatalf("mutations[%d] failed: %s", i, *m.Error)
		}
	}
	if *response.Cost <= 10000000 {
		t.Fatalf("the two mutations cost %d together, which is inside one budget: this case no longer distinguishes a shared budget from a per-mutation one", *response.Cost)
	}
	if len(response.ExceededBudgets) != 0 {
		t.Errorf("a budget was reported as exceeded: %v", *response.ExceededBudgets[0].Error)
	}
}

// A variable is bound afresh for every mutation, because upstream builds a new
// lazy `variables` map per ForInput. Two mutations that read one variable
// evaluate it twice and are charged twice, and the panel shows both.
func TestMutationVariablesAreChargedPerMutation(t *testing.T) {
	mutation := "  - patchType: ApplyConfiguration\n    applyConfiguration:\n      expression: >\n        Object{metadata: Object.metadata{labels: {%q: variables.appName}}}\n"
	policy := "apiVersion: admissionregistration.k8s.io/v1\nkind: MutatingAdmissionPolicy\nmetadata:\n  name: shared-variable\nspec:\n  failurePolicy: Fail\n  reinvocationPolicy: Never\n  variables:\n  - name: appName\n    expression: \"object.metadata.labels['app']\"\n  mutations:\n" +
		fmt.Sprintf(mutation, "first") + fmt.Sprintf(mutation, "second")

	out, err := k8s.EvalMutatingAdmissionPolicy([]byte(policy), nil, readMapFile(t, "object.yaml"), nil, nil, nil)
	if err != nil {
		t.Fatalf("EvalMutatingAdmissionPolicy() error: %v", err)
	}
	response := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if len(response.MutationVariables) != 2 {
		t.Fatalf("got %d variable rows, want one per mutation: %v", len(response.MutationVariables), response.MutationVariables)
	}
	for i, want := range []string{"mutations[0].appName", "mutations[1].appName"} {
		if response.MutationVariables[i].Name != want {
			t.Errorf("variable %d is named %q, want %q", i, response.MutationVariables[i].Name, want)
		}
		if response.MutationVariables[i].Cost == nil || *response.MutationVariables[i].Cost == 0 {
			t.Errorf("variable %d was not charged", i)
		}
	}
	// The total has to carry both, or a variable read twice is billed once.
	var variables uint64
	for _, v := range response.MutationVariables {
		variables += *v.Cost
	}
	var expressions uint64
	for _, m := range response.Mutations {
		expressions += *m.Cost
	}
	if *response.Cost != variables+expressions {
		t.Errorf("total cost %d, want %d (%d of variables and %d of expressions)", *response.Cost, variables+expressions, variables, expressions)
	}
}

// The apiserver's registry compiles a policy's matchConditions with a plain,
// non-composited compiler, so naming `variables` there is a compilation error
// and no cluster ever stores such a policy. That is true of a
// MutatingAdmissionPolicy for the same reason it is true of a validating one.
//
// Upstream: pkg/apis/admissionregistration/validation.validateMatchConditionsExpression,
// which uses getStrictStatelessCELCompiler().
func TestMutationMatchConditionsCannotReadVariables(t *testing.T) {
	policy := `apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata:
  name: variables-in-matchconditions
spec:
  failurePolicy: Fail
  reinvocationPolicy: Never
  variables:
  - name: appName
    expression: "object.metadata.labels['app']"
  matchConditions:
  - name: uses-a-variable
    expression: "variables.appName == 'nginx'"
  mutations:
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{metadata: Object.metadata{labels: {"touched": "true"}}}
`
	out, err := k8s.EvalMutatingAdmissionPolicy([]byte(policy), nil, readMapFile(t, "object.yaml"), nil, nil, nil)
	if err != nil {
		t.Fatalf("EvalMutatingAdmissionPolicy() error: %v", err)
	}
	response := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if len(response.MatchConditions) != 1 {
		t.Fatalf("got %d matchConditions, want 1", len(response.MatchConditions))
	}
	condition := response.MatchConditions[0]
	if !condition.IsError {
		t.Fatalf("the matchCondition compiled, want the error the registry gives")
	}
	if !strings.Contains(*condition.Error, "undeclared reference to 'variables'") {
		t.Errorf("error = %q, want it to name the undeclared reference", *condition.Error)
	}
	if len(response.Mutations) != 0 {
		t.Errorf("a mutation ran behind a matchCondition that cannot compile")
	}
}

// A field the schema does not declare is refused by a cluster before any policy
// runs. The playground has no such gate, so it says so -- and then must not
// blame the mutations for the field: reading the patched object back through
// the schema would fail for every one of them, on a fault that was in the input.
func TestMutationBlamesTheObjectForItsOwnUndeclaredFields(t *testing.T) {
	response := evalMutation(t, "jsonpatch label policy.yaml", "undeclared field object.yaml", "", "")

	if len(response.Warnings) != 1 {
		t.Fatalf("got %d warnings, want one about the object: %q", len(response.Warnings), response.Warnings)
	}
	if !strings.Contains(response.Warnings[0], "does not fit the Deployment schema") ||
		!strings.Contains(response.Warnings[0], "replicaz") {
		t.Errorf("warning = %q, want it to name the field the schema does not declare", response.Warnings[0])
	}
	if len(response.Mutations) != 1 {
		t.Fatalf("got %d mutations, want 1", len(response.Mutations))
	}
	if response.Mutations[0].IsError {
		t.Errorf("the mutation was blamed for a field the object already carried: %s", *response.Mutations[0].Error)
	}
	if response.FinalObject == "" {
		t.Errorf("nothing was applied, so the object-level warning cost the user the result as well")
	}
}

// Each mutation sees a fresh `variables` map, so the panel reports what that
// mutation read and nothing else. Sharing one map between them would report a
// variable against a mutation that never dereferenced it.
func TestMutationVariablesAreScopedToTheMutationThatReadThem(t *testing.T) {
	policy := `apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata:
  name: one-variable-each
spec:
  failurePolicy: Fail
  reinvocationPolicy: Never
  variables:
  - name: first
    expression: "'one'"
  - name: second
    expression: "'two'"
  mutations:
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{metadata: Object.metadata{labels: {"a": variables.first}}}
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{metadata: Object.metadata{labels: {"b": variables.second}}}
`
	out, err := k8s.EvalMutatingAdmissionPolicy([]byte(policy), nil, readMapFile(t, "object.yaml"), nil, nil, nil)
	if err != nil {
		t.Fatalf("EvalMutatingAdmissionPolicy() error: %v", err)
	}
	response := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	var names []string
	for _, variable := range response.MutationVariables {
		names = append(names, variable.Name)
	}
	want := []string{"mutations[0].first", "mutations[1].second"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("variables reported as %v, want %v", names, want)
	}
}

// The per-object ceiling bounds one mutation's output; nothing bounds how many
// mutations a policy declares. A hundred of them, each echoing an object grown
// to just under the ceiling, is megabytes of response for a kilobyte of policy
// and a few hundred units of CEL cost -- the same attack the ceiling exists for,
// arrived at from the other direction.
func TestMutationBoundsWhatTheWholePolicyReports(t *testing.T) {
	// The first mutation inflates the object by copying its spec into itself,
	// stopping under the per-object ceiling; the rest each touch one field, so
	// each one's output is another copy of that inflated object.
	var copies []string
	for i := range 8 {
		copies = append(copies, fmt.Sprintf(`JSONPatch{op: "copy", from: "/spec", path: "/spec/x%d"}`, i))
	}
	policy := "apiVersion: admissionregistration.k8s.io/v1\nkind: MutatingAdmissionPolicy\nmetadata:\n  name: echo\nspec:\n  failurePolicy: Ignore\n  reinvocationPolicy: Never\n  mutations:\n" +
		"  - patchType: JSONPatch\n    jsonPatch:\n      expression: '[" + strings.Join(copies, ", ") + "]'\n"
	const echoes = 40
	for i := range echoes {
		policy += fmt.Sprintf("  - patchType: JSONPatch\n    jsonPatch:\n      expression: '[JSONPatch{op: \"add\", path: \"/metadata/annotations\", value: {}}, JSONPatch{op: \"add\", path: \"/metadata/annotations/e%d\", value: \"x\"}]'\n", i)
	}

	out, err := k8s.EvalMutatingAdmissionPolicy([]byte(policy), nil, readMapFile(t, "bomb object.yaml"), nil, nil, nil)
	if err != nil {
		t.Fatalf("EvalMutatingAdmissionPolicy() error: %v", err)
	}
	response := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if len(response.Mutations) != echoes+1 {
		t.Fatalf("got %d mutations, want %d", len(response.Mutations), echoes+1)
	}
	for i, mutation := range response.Mutations {
		if mutation.IsError {
			t.Fatalf("mutations[%d] failed, so this case no longer produces a large response: %s", i, *mutation.Error)
		}
	}
	// The policy is ~6 KB and the object 400 bytes. Without a ceiling on the
	// whole response this is tens of megabytes.
	if len(out) > 3*1024*1024 {
		t.Errorf("the response is %d bytes for a %d-byte policy", len(out), len(policy))
	}
	if response.FinalObject == "" {
		t.Errorf("the response was trimmed to nothing; the final object is what carries the answer")
	}
	withheld := 0
	for _, mutation := range response.Mutations {
		if mutation.MutatedObject == "" && mutation.Message != "" {
			withheld++
		}
	}
	if withheld == 0 {
		t.Errorf("every mutation's object was reported, so nothing was bounded")
	}
	t.Logf("policy %d bytes, response %d bytes, %d of %d per-mutation objects withheld", len(policy), len(out), withheld, len(response.Mutations))
}

// The validating mode ignores spec.matchConstraints and spec.paramKind for the
// same reasons the mutating one does, and has to say so in the same place. A
// reader moving between the two modes would otherwise conclude that the one
// that says nothing does evaluate them.
func TestValidatingReportsWhatItDoesNotSimulate(t *testing.T) {
	policy := `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: caveats
spec:
  paramKind:
    apiVersion: v1
    kind: ConfigMap
  matchConstraints:
    resourceRules:
    - apiGroups:   ["apps"]
      apiVersions: ["v1"]
      operations:  ["CREATE"]
      resources:   ["deployments"]
  validations:
  - expression: "true"
`
	out, err := k8s.EvalValidatingAdmissionPolicy([]byte(policy), nil, readMapFile(t, "object.yaml"), nil, nil, nil)
	if err != nil {
		t.Fatalf("EvalValidatingAdmissionPolicy() error: %v", err)
	}
	response := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	for _, want := range []string{"matchConstraints:", "paramKind:", "API defaults:"} {
		if !strings.Contains(response.NotSimulated, want) {
			t.Errorf("notSimulated does not mention %q:\n%s", want, response.NotSimulated)
		}
	}
	if strings.Contains(response.NotSimulated, "reinvocationPolicy") {
		t.Errorf("the validating mode claims not to reinvoke, which it never would:\n%s", response.NotSimulated)
	}
}

// The webhook mode evaluates matchConditions and nothing else, and says so in
// the same place the two policy modes do -- a reader trained by them to look
// for the section should not find silence.
func TestWebhookReportsWhatItDoesNotSimulate(t *testing.T) {
	configuration := `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: hooks
webhooks:
  - name: hook.example.com
    sideEffects: None
    admissionReviewVersions: ["v1"]
    matchConditions:
      - name: always
        expression: "true"
`
	out, err := k8s.EvalWebhook([]byte(configuration), nil, readMapFile(t, "object.yaml"), nil, nil)
	if err != nil {
		t.Fatalf("EvalWebhook() error: %v", err)
	}
	response := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	for _, want := range []string{"rules, namespaceSelector and objectSelector", "not called"} {
		if !strings.Contains(response.NotSimulated, want) {
			t.Errorf("notSimulated does not mention %q:\n%s", want, response.NotSimulated)
		}
	}
}

// A mutation that spends more than its budget is abandoned by the apiserver and
// the request fails. There is no remaining budget to subtract afterwards, so the
// cost is unknown -- but the overrun is the one thing the budget section exists
// to report, and reporting nothing was worse than reporting no number.
func TestMutationReportsItsOwnBudgetOverrun(t *testing.T) {
	// celconfig.PerCallLimit caps any single expression at 1,000,000, so the
	// only way past the 10,000,000 budget is across variables. Sixteen of two
	// authorizer checks each is about 11 million.
	const variables = 16
	check := func(verb string) string {
		return fmt.Sprintf("string(authorizer.group('apps').resource('deployments').check('%s').allowed())", verb)
	}
	declarations, reads := "", make([]string, 0, variables)
	for i := range variables {
		declarations += fmt.Sprintf("  - name: v%d\n    expression: \"%s + %s\"\n",
			i, check(fmt.Sprintf("a%d", i)), check(fmt.Sprintf("b%d", i)))
		reads = append(reads, fmt.Sprintf("%q: variables.v%d", fmt.Sprintf("v%d", i), i))
	}
	policy := "apiVersion: admissionregistration.k8s.io/v1\nkind: MutatingAdmissionPolicy\nmetadata:\n  name: overrun\nspec:\n  failurePolicy: Fail\n  reinvocationPolicy: Never\n  variables:\n" + declarations +
		"  mutations:\n  - patchType: ApplyConfiguration\n    applyConfiguration:\n      expression: >\n        Object{metadata: Object.metadata{annotations: {" + strings.Join(reads, ", ") + "}}}\n"

	out, err := k8s.EvalMutatingAdmissionPolicy([]byte(policy), nil, readMapFile(t, "object.yaml"), nil, nil, nil)
	if err != nil {
		t.Fatalf("EvalMutatingAdmissionPolicy() error: %v", err)
	}
	response := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if len(response.Mutations) != 1 || !response.Mutations[0].IsError {
		t.Fatalf("the mutation was applied; this case no longer overruns the budget: %s", out)
	}
	if len(response.ExceededBudgets) != 1 {
		t.Fatalf("got %d exceeded budgets, want one naming the mutation: %s", len(response.ExceededBudgets), out)
	}
	if got := *response.ExceededBudgets[0].Name; got != "mutations[0]" {
		t.Errorf("the overrun is reported against %q, want mutations[0]", got)
	}
}

// ApplyStructuredMergeDiff parses objects with typed.AllowDuplicates, so a
// duplicate entry in an associative list is something the merge copes with, and
// both probes here allow them too. A cluster refuses such an object -- but at
// validation, for having two containers of one name, not at decoding, and the
// playground does not validate objects at all. Reporting it as a schema
// mismatch would name the wrong gate and switch off the patched-object
// read-back for every mutation on the strength of it.
func TestMutationToleratesADuplicateListEntry(t *testing.T) {
	object := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.27
      - name: nginx
        image: nginx:1.28
`
	out, err := k8s.EvalMutatingAdmissionPolicy(
		readMapFile(t, "applyconfig label policy.yaml"), nil, []byte(object), nil, nil, nil)
	if err != nil {
		t.Fatalf("EvalMutatingAdmissionPolicy() error: %v", err)
	}
	response := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if len(response.Warnings) != 0 {
		t.Errorf("a duplicate list entry was reported as a schema mismatch: %q", response.Warnings)
	}
	if response.Mutations[0].IsError {
		t.Errorf("the mutation was refused: %s", *response.Mutations[0].Error)
	}
}

// The two halves of a MutatingAdmissionPolicy read the same request. The
// matchConditions are evaluated here and the mutations by upstream's patcher,
// which rebuilds the request from the admission attributes and the matched
// group-version it is handed -- so those have to be the same three things
// newEvalInputs derived `request` from, or one expression answers differently
// depending on which half of the policy it sits in.
func TestMutationSeesTheSameRequestAsItsMatchConditions(t *testing.T) {
	request := `
kind:
  group: apps
  version: v1
  kind: Deployment
resource:
  group: apps
  version: v1
  resource: deployments
requestKind:
  group: apps
  version: v1beta1
  kind: Deployment
requestResource:
  group: apps
  version: v1beta1
  resource: deployments
name: nginx
namespace: default
operation: UPDATE
userInfo:
  username: alice
`
	policy := `apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata:
  name: same-request
spec:
  failurePolicy: Fail
  reinvocationPolicy: Never
  matchConditions:
  - name: matched-at-v1
    expression: "request.kind.version == 'v1' && request.requestKind.version == 'v1beta1' && request.operation == 'UPDATE'"
  mutations:
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{
          metadata: Object.metadata{
            annotations: {
              "kind": request.kind.version,
              "requestKind": request.requestKind.version,
              "operation": string(request.operation)
            }
          }
        }
`
	out, err := k8s.EvalMutatingAdmissionPolicy([]byte(policy), nil, readMapFile(t, "object.yaml"), nil, []byte(request), nil)
	if err != nil {
		t.Fatalf("EvalMutatingAdmissionPolicy() error: %v", err)
	}
	response := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if len(response.MatchConditions) != 1 || response.MatchConditions[0].Result != true {
		t.Fatalf("the matchCondition did not read the request as expected: %s", out)
	}
	for _, want := range []string{"kind: v1", "requestKind: v1beta1", "operation: UPDATE"} {
		if !strings.Contains(response.FinalObject, want) {
			t.Errorf("the mutation did not read %q from the same request the matchCondition saw:\n%s", want, response.FinalObject)
		}
	}
}

// An object with no apiVersion or kind cannot be mutated: the merge needs a
// type to look up and the patchers need a group-version to stamp on the patch.
// A cluster never sees such an object -- it would not have decoded -- so this
// is the playground telling the user to finish the tab, not a cluster
// behaviour being reproduced.
func TestMutationNeedsTheObjectsGroupVersionKind(t *testing.T) {
	for _, object := range []string{
		"metadata:\n  name: nginx\n",
		"kind: Deployment\nmetadata:\n  name: nginx\n",
	} {
		out, err := k8s.EvalMutatingAdmissionPolicy(
			readMapFile(t, "applyconfig label policy.yaml"), nil, []byte(object), nil, nil, nil)
		if err != nil {
			t.Fatalf("EvalMutatingAdmissionPolicy() error: %v", err)
		}
		response := k8s.EvalResponse{}
		if err := json.Unmarshal([]byte(out), &response); err != nil {
			t.Fatalf("json.Unmarshal() error: %v", err)
		}
		if len(response.Mutations) != 1 || !response.Mutations[0].IsError {
			t.Fatalf("an object without a kind was mutated: %s", out)
		}
		if !strings.Contains(*response.Mutations[0].Error, "apiVersion and kind") {
			t.Errorf("error = %q, want it to name what is missing", *response.Mutations[0].Error)
		}
		// An unfinished tab is not a cluster refusing anything, so the decision
		// must not quote failurePolicy at the reader.
		message, _ := response.Decision[0].Message.(string)
		if !strings.Contains(message, "no decision") {
			t.Errorf("decision = %q, want it to say there is no decision to report", message)
		}
	}
}

// A variable may be bound to the whole object, and every mutation gets its own
// copy of every variable it reads. The per-object ceiling does not touch those,
// so without a ceiling of their own the response grows with the length of the
// policy: inflate a small object once, then read it back from a hundred
// mutations, and a 16 KB policy answers with tens of megabytes for a few
// thousand units of CEL cost.
func TestMutationBoundsTheValuesItReports(t *testing.T) {
	var copies []string
	for i := range 9 {
		copies = append(copies, fmt.Sprintf(`JSONPatch{op: "copy", from: "/spec", path: "/spec/x%d"}`, i))
	}
	policy := "apiVersion: admissionregistration.k8s.io/v1\nkind: MutatingAdmissionPolicy\nmetadata:\n  name: echo-variables\nspec:\n  failurePolicy: Ignore\n  reinvocationPolicy: Never\n  variables:\n  - name: snap\n    expression: \"object\"\n  mutations:\n" +
		"  - patchType: JSONPatch\n    jsonPatch:\n      expression: '[" + strings.Join(copies, ", ") + "]'\n"
	const echoes = 60
	for i := range echoes {
		policy += fmt.Sprintf("  - patchType: JSONPatch\n    jsonPatch:\n      expression: '[JSONPatch{op: \"add\", path: \"/metadata/annotations\", value: {}}, JSONPatch{op: \"add\", path: \"/metadata/annotations/e%d\", value: string(size(variables.snap))}]'\n", i)
	}

	out, err := k8s.EvalMutatingAdmissionPolicy([]byte(policy), nil, readMapFile(t, "bomb object.yaml"), nil, nil, nil)
	if err != nil {
		t.Fatalf("EvalMutatingAdmissionPolicy() error: %v", err)
	}
	response := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if len(response.MutationVariables) != echoes {
		t.Fatalf("got %d variable rows, want one per echoing mutation (%d)", len(response.MutationVariables), echoes)
	}
	if len(out) > 3*1024*1024 {
		t.Errorf("the response is %d bytes for a %d-byte policy", len(out), len(policy))
	}
	withheld := 0
	for _, variable := range response.MutationVariables {
		if value, ok := variable.Value.(string); ok && strings.HasPrefix(value, "(not shown") {
			withheld++
		}
		if variable.Cost == nil {
			t.Errorf("a withheld variable lost its cost as well as its value")
		}
	}
	if withheld == 0 {
		t.Fatalf("every variable value was reported, so nothing was bounded")
	}
	t.Logf("policy %d bytes, response %d bytes, %d of %d variable values withheld", len(policy), len(out), withheld, len(response.MutationVariables))
}

// A diff too large to send back is withheld, and the decision has to keep
// telling the truth about whether the object changed: "left the object
// unchanged" and "the diff is not shown" are different sentences and the panel
// has only one place to say either.
func TestMutationSaysTheObjectChangedEvenWhenTheDiffIsWithheld(t *testing.T) {
	// A custom resource, so nothing reads it back against a schema, with a list
	// long enough that rewriting every entry produces a diff past the ceiling.
	var parts []string
	for i := range 20000 {
		parts = append(parts, fmt.Sprintf("  - name: part-%05d\n    size: %d\n", i, i))
	}
	object := "apiVersion: example.com/v1\nkind: Widget\nmetadata:\n  name: big\n  namespace: default\nspec:\n  parts:\n" + strings.Join(parts, "")
	policy := `apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata:
  name: rewrite-every-entry
spec:
  failurePolicy: Fail
  reinvocationPolicy: Never
  mutations:
  - patchType: JSONPatch
    jsonPatch:
      expression: >
        [JSONPatch{op: "replace", path: "/spec/parts", value: object.spec.parts.map(p, {"name": string(p.name) + "-renamed"})}]
`
	out, err := k8s.EvalMutatingAdmissionPolicy([]byte(policy), nil, []byte(object), nil, nil, nil)
	if err != nil {
		t.Fatalf("EvalMutatingAdmissionPolicy() error: %v", err)
	}
	response := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if response.Mutations[0].IsError {
		t.Fatalf("the mutation failed, so this case no longer produces a large diff: %s", *response.Mutations[0].Error)
	}
	if response.Diff != "" {
		t.Fatalf("the diff was %d bytes and not withheld; this case no longer exercises the ceiling", len(response.Diff))
	}
	message, _ := response.Decision[0].Message.(string)
	if strings.Contains(message, "unchanged") {
		t.Errorf("decision = %q, and every entry in the list changed", message)
	}
	found := false
	for _, warning := range response.Warnings {
		if strings.Contains(warning, "no diff is shown") {
			found = true
		}
	}
	if !found {
		t.Errorf("the diff was withheld and nothing says so: %q", response.Warnings)
	}
}

// A patched object the apiserver cannot decode comes back as a StatusError, and
// the dispatcher returns those rather than collecting them -- so the mutations
// after it never run, where an ordinary failure lets them.
func TestAFatalMutationStopsTheOnesAfterIt(t *testing.T) {
	policy := `apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata:
  name: fatal-first
spec:
  failurePolicy: Ignore
  reinvocationPolicy: Never
  mutations:
  - patchType: JSONPatch
    jsonPatch:
      expression: '[JSONPatch{op: "replace", path: "/spec/replicas", value: "10"}]'
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{metadata: Object.metadata{labels: {"second": "ran"}}}
`
	out, err := k8s.EvalMutatingAdmissionPolicy([]byte(policy), nil, readMapFile(t, "object.yaml"), nil, nil, nil)
	if err != nil {
		t.Fatalf("EvalMutatingAdmissionPolicy() error: %v", err)
	}
	response := k8s.EvalResponse{}
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if len(response.Mutations) != 1 {
		t.Fatalf("got %d mutations, want only the one that aborted the dispatch", len(response.Mutations))
	}
	if response.FinalObject != "" {
		t.Errorf("an object was reported after the dispatch aborted:\n%s", response.FinalObject)
	}
	message, _ := response.Decision[0].Message.(string)
	if !strings.Contains(message, "whatever failurePolicy says") {
		t.Errorf("decision = %q, want it to say failurePolicy does not excuse this", message)
	}
}
