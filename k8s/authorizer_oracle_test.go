// Copyright 2024 Undistro Authors
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
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	"gopkg.in/yaml.v3"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/cel/library"

	"github.com/undistro/cel-playground/k8s"
)

// These tests run each expression twice -- through this repo's authorizer and
// through the one Kubernetes itself uses -- and require the same answer. One place
// to catch three things: this repo drifting from Kubernetes, a Kubernetes upgrade
// changing what an expression means, and a chain that answers a question other than
// the one it was asked.
//
// Kubernetes' side is k8s.io/apiserver/pkg/cel/library's Authz, the library an
// apiserver uses for the authorizer variable. It is given a stand-in authorizer
// that records which check an expression came down to. This repo answers from an
// Authorizer tab instead, so that recorded check is written out as a tab allowing
// exactly it, and the same expression has to report allowed here. Tabs built from
// the same check with one field altered have to report not allowed, which is what
// catches a chain that drops part of its scoping and matches anyway.
//
// Only semantics are compared. Costs are not: this repo parses where the
// apiserver compiles, so overloads that need type information fall back to
// cel-go's defaults and the two legitimately disagree.
//
// Two differences between the two are stepped around rather than compared, and no
// expression below runs into one: check("") errors here where Kubernetes asks about
// the empty verb, and serviceAccount() here accepts a namespace and a name
// Kubernetes rejects as invalid. A row that runs into one of those fails, and the
// disagreement is real rather than a mistake in the row.
//
// fieldSelector() and labelSelector() are outside the comparison altogether: they
// come from library.AuthzSelectors, which the environment below does not register,
// and this repo has no receiver for them at all.

// recordingAuthorizer keeps the attributes of the last check it was asked about.
// Kubernetes' library builds them from the chain of calls, which is the part
// being compared.
type recordingAuthorizer struct {
	attributes authorizer.Attributes
}

func (r *recordingAuthorizer) Authorize(_ context.Context, attributes authorizer.Attributes) (
	authorizer.Decision, string, error) {
	r.attributes = attributes
	return authorizer.DecisionAllow, "", nil
}

// oracleUser is who the chains below ask as, unless a chain calls
// serviceAccount(). Its name must not look like a service account's, or
// authorizerTab would nest every tab under serviceAccounts: and no chain would
// find its own check.
var oracleUser = &user.DefaultInfo{Name: "someone", Groups: []string{"system:authenticated"}}

// recordedCheck evaluates expression against Kubernetes' own authorizer library
// and reports the check it decided the expression was asking about. The returned
// record is a copy, so a caller can alter a field to build a check that must not
// match. It carries every field the Authorizer tab can express; the library also
// sets an API version of "*", which the tab has no key for.
//
// A returned error is the library refusing to answer the expression, which is what
// TestAuthorizerRejectsWhatKubernetesRejects is about. An expression the library
// cannot compile, or one that never reaches the authorizer, is a fault in this
// file and fails the test outright.
func recordedCheck(t *testing.T, expression string) (authorizer.AttributesRecord, error) {
	t.Helper()

	env, err := cel.NewEnv(library.Authz(), cel.Variable("authorizer", library.AuthorizerType))
	if err != nil {
		t.Fatalf("cel.NewEnv() with the Authz library: %v", err)
	}
	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("compiling %q against the Authz library: %v", expression, issues.Err())
	}
	program, err := env.Program(ast)
	if err != nil {
		t.Fatalf("env.Program() for %q: %v", expression, err)
	}

	recorder := &recordingAuthorizer{}
	if _, _, err := program.Eval(map[string]any{
		"authorizer": library.NewAuthorizerVal(oracleUser, recorder),
	}); err != nil {
		return authorizer.AttributesRecord{}, err
	}
	if recorder.attributes == nil {
		t.Fatalf("evaluating %q asked the authorizer nothing", expression)
	}

	attributes := recorder.attributes
	return authorizer.AttributesRecord{
		User:            attributes.GetUser(),
		Verb:            attributes.GetVerb(),
		APIGroup:        attributes.GetAPIGroup(),
		Resource:        attributes.GetResource(),
		Subresource:     attributes.GetSubresource(),
		Namespace:       attributes.GetNamespace(),
		Name:            attributes.GetName(),
		ResourceRequest: attributes.IsResourceRequest(),
		Path:            attributes.GetPath(),
	}, nil
}

// authorizerTab writes the Authorizer tab that allows exactly one check and
// nothing else. A check on deployments/scale named nginx in namespace default,
// verb update, comes out as
//
//	groups:
//	    apps:
//	        resources:
//	            deployments:
//	                subresources:
//	                    scale:
//	                        checks:
//	                            default:
//	                                nginx:
//	                                    update:
//	                                        decision: allow
//	                                        reason: matched-the-recorded-check
//
// A check with no subresource keeps that same checks: block directly under the
// resource. A non-resource check is written under paths:, keyed by path and then
// by verb. A check made as a service account nests all of the above under
// serviceAccounts: <namespace>: <name>:. A group, namespace or name the chain
// never set is written as an empty key: the fixture matches its keys exactly, so
// "" is a key like any other.
func authorizerTab(t *testing.T, check authorizer.AttributesRecord) []byte {
	t.Helper()

	decision := map[string]any{"decision": "allow", "reason": "matched-the-recorded-check"}

	var tab map[string]any
	if check.ResourceRequest {
		entry := map[string]any{}
		checks := map[string]any{
			check.Namespace: map[string]any{
				check.Name: map[string]any{check.Verb: decision},
			},
		}
		if check.Subresource == "" {
			entry["checks"] = checks
		} else {
			// A subresource keeps its checks in its own entry under the resource.
			entry["subresources"] = map[string]any{
				check.Subresource: map[string]any{"checks": checks},
			}
		}
		tab = map[string]any{
			"groups": map[string]any{
				check.APIGroup: map[string]any{
					"resources": map[string]any{check.Resource: entry},
				},
			},
		}
	} else {
		tab = map[string]any{
			"paths": map[string]any{
				check.Path: map[string]any{"checks": map[string]any{check.Verb: decision}},
			},
		}
	}

	// A chain through serviceAccount() reads a whole tab of its own, and the
	// service account it asks about is the user on the recorded check.
	if namespace, name, ok := serviceAccountName(check.User); ok {
		tab = map[string]any{
			"serviceAccounts": map[string]any{namespace: map[string]any{name: tab}},
		}
	}

	out, err := yaml.Marshal(tab)
	if err != nil {
		t.Fatalf("marshalling the authorizer tab: %v", err)
	}
	return out
}

// serviceAccountName splits the user name the library gives a check made through
// serviceAccount(), "system:serviceaccount:<namespace>:<name>", into the two keys
// the tab nests that service account under. Any other user reports false.
func serviceAccountName(info user.Info) (namespace, name string, ok bool) {
	if info == nil {
		return "", "", false
	}
	namespace, name, err := serviceaccount.SplitUsername(info.GetName())
	if err != nil {
		return "", "", false
	}
	return namespace, name, true
}

// evaluate runs one expression through the playground's own evaluator, as the
// single validation of a policy, with the given Authorizer tab, and reports what
// that validation said.
//
// The expression is spliced into a single-quoted YAML scalar, so it must not
// contain a single quote. There is no object being admitted and no request: every
// chain here takes its scoping from string literals, and nothing but the
// expression and the tab reaches the authorizer.
func evaluate(t *testing.T, expression string, tab []byte) *k8s.EvalResult {
	t.Helper()

	policy := []byte(`apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: "authorizer-oracle.example.com"
spec:
  validations:
  - expression: '` + expression + `'
`)
	empty := []byte("")

	out, err := k8s.EvalValidatingAdmissionPolicy(policy, empty, empty, empty, empty, tab)
	if err != nil {
		t.Fatalf("EvalValidatingAdmissionPolicy() for %q: %v", expression, err)
	}
	var response k8s.EvalResponse
	if err := json.Unmarshal([]byte(out), &response); err != nil {
		t.Fatalf("unmarshalling the response for %q: %v", expression, err)
	}
	if len(response.Validations) != 1 {
		t.Fatalf("validations = %+v, want exactly one", response.Validations)
	}
	return response.Validations[0]
}

func TestAuthorizerChainsAskWhatKubernetesAsks(t *testing.T) {
	expressions := []string{
		`authorizer.group("apps").resource("deployments").check("create").allowed()`,
		`authorizer.group("").resource("pods").check("get").allowed()`,
		// Whatever an argument was written with is what the check is about, padding
		// included, because the fixture matches its keys exactly. A verb is an
		// argument like any other: Kubernetes asks the cluster about it rather than
		// refusing it, so only an empty one is refused here.
		`authorizer.group(" apps ").resource("deployments").name(" nginx ").check("update").allowed()`,
		`authorizer.group("apps").resource("deployments").check("  ").allowed()`,
		`authorizer.group("apps").resource("deployments").subresource("status").check("update").allowed()`,
		`authorizer.group("apps").resource("deployments").namespace("default").check("update").allowed()`,
		`authorizer.group("apps").resource("deployments").namespace("default").name("nginx").check("update").allowed()`,
		`authorizer.group("apps").resource("deployments").subresource("scale").namespace("default").name("nginx").check("update").allowed()`,
		// The scoping calls in a different order, which must not change the check.
		`authorizer.group("apps").resource("deployments").name("nginx").namespace("default").subresource("scale").check("update").allowed()`,
		// A second call to the same scoping function, and an empty argument.
		// Kubernetes answers both: the later call replaces what the earlier one
		// set, and an empty argument puts the field back to empty -- for
		// namespace() that is the cluster scope, not every namespace.
		`authorizer.group("apps").resource("deployments").namespace("kube-system").namespace("default").check("update").allowed()`,
		`authorizer.group("apps").resource("deployments").namespace("default").namespace("").check("update").allowed()`,
		`authorizer.group("apps").resource("deployments").name("nginx").name("").check("update").allowed()`,
		`authorizer.group("apps").resource("deployments").subresource("status").subresource("scale").check("update").allowed()`,
		`authorizer.group("apps").resource("deployments").subresource("scale").subresource("").check("update").allowed()`,
		// A non-resource path, and a check made as a service account. Asking as one
		// replaces who is asking, so a second serviceAccount() is the account the
		// check is about -- it does not look for that account inside the first.
		`authorizer.path("/healthz").check("get").allowed()`,
		`authorizer.serviceAccount("default", "builder").group("apps").resource("deployments").namespace("default").check("update").allowed()`,
		`authorizer.serviceAccount("kube-system", "other").serviceAccount("default", "builder").group("apps").resource("deployments").namespace("default").check("update").allowed()`,
	}

	for _, expression := range expressions {
		t.Run(expression, func(t *testing.T) {
			check, err := recordedCheck(t, expression)
			if err != nil {
				t.Fatalf("Kubernetes' own library could not evaluate this: %v", err)
			}

			result := evaluate(t, expression, authorizerTab(t, check))
			if result.IsError {
				t.Fatalf("the tab allowing the recorded check reported an error: %v", *result.Error)
			}
			if result.Result != true {
				t.Errorf("the tab allowing %s reported %v, want true -- "+
					"this chain asked about something else", describe(check), result.Result)
			}

			// Each part of the scoping has to matter. A tab that allows a check
			// differing in one field only must not answer this chain.
			for field, altered := range alterations(check) {
				t.Run("not "+field, func(t *testing.T) {
					result := evaluate(t, expression, authorizerTab(t, altered))
					if result.IsError {
						t.Fatalf("altered tab reported an error: %v", *result.Error)
					}
					if result.Result != false {
						t.Errorf("a tab allowing only %s reported %v, want false",
							describe(altered), result.Result)
					}
				})
			}
		})
	}
}

// alterations returns copies of a check that differ from it in one field, each
// one a check the chain must not match.
func alterations(check authorizer.AttributesRecord) map[string]authorizer.AttributesRecord {
	altered := map[string]authorizer.AttributesRecord{}

	withVerb := check
	withVerb.Verb += "-something-else"
	altered["verb"] = withVerb

	// Which service account a chain asks as is part of the check too: the tab it
	// reads is nested under exactly that namespace and name.
	if namespace, name, ok := serviceAccountName(check.User); ok {
		withServiceAccountName := check
		withServiceAccountName.User = &user.DefaultInfo{
			Name: serviceaccount.MakeUsername(namespace, name+"-something-else"),
		}
		altered["service account name"] = withServiceAccountName

		withServiceAccountNamespace := check
		withServiceAccountNamespace.User = &user.DefaultInfo{
			Name: serviceaccount.MakeUsername(namespace+"-something-else", name),
		}
		altered["service account namespace"] = withServiceAccountNamespace
	}

	if !check.ResourceRequest {
		withPath := check
		withPath.Path += "-something-else"
		altered["path"] = withPath
		return altered
	}

	withNamespace := check
	withNamespace.Namespace += "-something-else"
	altered["namespace"] = withNamespace

	withName := check
	withName.Name += "-something-else"
	altered["name"] = withName

	withSubresource := check
	withSubresource.Subresource += "-something-else"
	altered["subresource"] = withSubresource

	withResource := check
	withResource.Resource += "-something-else"
	altered["resource"] = withResource

	withGroup := check
	withGroup.APIGroup += "-something-else"
	altered["group"] = withGroup

	return altered
}

func describe(check authorizer.AttributesRecord) string {
	as := ""
	if namespace, name, ok := serviceAccountName(check.User); ok {
		as = fmt.Sprintf(", as service account %q in namespace %q", name, namespace)
	}
	if !check.ResourceRequest {
		return fmt.Sprintf("path %q, verb %q", check.Path, check.Verb) + as
	}
	return fmt.Sprintf("group %q, resource %q, subresource %q, namespace %q, name %q, verb %q",
		check.APIGroup, check.Resource, check.Subresource, check.Namespace, check.Name, check.Verb) + as
}

// TestAuthorizerRejectsWhatKubernetesRejects covers the empty-argument calls
// Kubernetes answers with an error rather than with a decision, where the message
// is part of what a user reads.
func TestAuthorizerRejectsWhatKubernetesRejects(t *testing.T) {
	expressions := []string{
		`authorizer.group("apps").resource("").check("update").allowed()`,
		`authorizer.path("").check("get").allowed()`,
		// A whitespace-only argument is the one place the trimming above agrees
		// with Kubernetes, which trims these two to test them for emptiness.
		`authorizer.group("apps").resource("  ").check("update").allowed()`,
		`authorizer.path("  ").check("get").allowed()`,
	}

	for _, expression := range expressions {
		t.Run(expression, func(t *testing.T) {
			if _, err := recordedCheck(t, expression); err == nil {
				t.Fatalf("Kubernetes' own library answered this rather than erroring")
			} else {
				result := evaluate(t, expression, []byte("paths:\ngroups:\nserviceAccounts:\n"))
				if !result.IsError {
					t.Fatalf("answered %v, want the error Kubernetes gives: %v", result.Result, err)
				}
				if !strings.Contains(*result.Error, err.Error()) {
					t.Errorf("error = %q, want it to carry Kubernetes' own message %q",
						*result.Error, err.Error())
				}
			}
		})
	}
}

// TestAuthorizerCoversTheAuthzLibrary compares the functions Kubernetes' authorizer
// libraries declare against the ones the receivers here answer. A dependency bump
// that adds a function -- fieldSelector() and labelSelector() arrived that way --
// fails here rather than reaching a user as "no such overload", and a receiver
// dropped from authorizer.go fails here too.
func TestAuthorizerCoversTheAuthzLibrary(t *testing.T) {
	// One expression per declared function, each ending in a value a validation can
	// report. A function with no receiver here maps to the empty string.
	expressions := map[string]string{
		"path":           `authorizer.path("/healthz").check("get").allowed()`,
		"group":          `authorizer.group("apps").resource("deployments").check("update").allowed()`,
		"resource":       `authorizer.group("apps").resource("deployments").check("update").allowed()`,
		"serviceAccount": `authorizer.serviceAccount("default", "builder").group("apps").resource("deployments").check("update").allowed()`,
		"subresource":    `authorizer.group("apps").resource("deployments").subresource("scale").check("update").allowed()`,
		"namespace":      `authorizer.group("apps").resource("deployments").namespace("default").check("update").allowed()`,
		"name":           `authorizer.group("apps").resource("deployments").name("nginx").check("update").allowed()`,
		"check":          `authorizer.group("apps").resource("deployments").check("update").allowed()`,
		"allowed":        `authorizer.group("apps").resource("deployments").check("update").allowed()`,
		"reason":         `authorizer.group("apps").resource("deployments").check("update").reason()`,
		"errored":        `authorizer.group("apps").resource("deployments").check("update").errored()`,
		"error":          `authorizer.group("apps").resource("deployments").check("update").error()`,
		// From library.AuthzSelectors, which k8s/cel.go does not register and which
		// has no receiver here: a chain using one errors rather than answering.
		"fieldSelector": "",
		"labelSelector": "",
	}

	standard, err := cel.NewEnv()
	if err != nil {
		t.Fatalf("cel.NewEnv() with no libraries: %v", err)
	}
	withAuthz, err := cel.NewEnv(library.Authz(), library.AuthzSelectors())
	if err != nil {
		t.Fatalf("cel.NewEnv() with the Authz libraries: %v", err)
	}

	for name := range withAuthz.Functions() {
		if _, standardFunction := standard.Functions()[name]; standardFunction {
			continue
		}
		expression, known := expressions[name]
		if !known {
			t.Errorf("the Authz libraries declare %q, which this repo does not answer "+
				"and authorizer.go has no receiver for", name)
			continue
		}
		if expression == "" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			result := evaluate(t, expression, []byte("paths:\ngroups:\nserviceAccounts:\n"))
			if result.IsError {
				t.Errorf("%s reported an error rather than answering: %v", expression, *result.Error)
			}
		})
	}

	for name := range expressions {
		if _, declared := withAuthz.Functions()[name]; !declared {
			t.Errorf("%q is answered here but the Authz libraries no longer declare it", name)
		}
	}
}
