// Copyright 2026 Undistro Authors
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
	"bytes"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	"gopkg.in/yaml.v3"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/cel/library"
	rbacvalidation "k8s.io/kubernetes/pkg/registry/rbac/validation"
	rbacauthorizer "k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"

	"github.com/undistro/cel-playground/k8s"
)

// These tests ask a different question from the ones in
// authorizer_oracle_test.go next door. Those drive Kubernetes' authorizer
// library with a recorder that allows everything, so they compare the check an
// expression *asks* -- the group, resource, namespace and name it fills in.
// They say nothing about how an authorizer answers it, because the recorder
// never decides anything.
//
// These run the real thing instead: Kubernetes' RBAC authorizer, over roles and
// bindings, answering for itself. The Authorizer tab is written from the same
// grant the cluster was given rather than from the check, which is what someone
// using the playground does -- they transcribe the RBAC they have, and then ask
// whatever their policy asks. Neither side is told what the other said.
//
// What that leaves out is everything RBAC cannot express. RBAC never denies, it
// only declines to allow, so nothing here pins what a `deny:` entry does, nor
// which of two entries that both answer is preferred, since no cluster can be
// configured to carve an exception out of a broader grant. Those are the
// fixture's own semantics: TestAuthorizerPrefersTheNarrowerEntry below covers
// them, and the vap fixture cases cover a decision that is not an allow.
//
// oracleUser and evaluate are shared with authorizer_oracle_test.go.

// grant is a set of rules given to oracleUser, cluster-wide when namespace is
// empty and in that namespace otherwise.
type grant struct {
	name      string
	namespace string
	// serviceAccount, as "namespace/name", binds the rules to a service account
	// instead of to oracleUser. A policy reaches it with serviceAccount(), and
	// the tab keys it under its own section.
	serviceAccount string
	rules          []rbacv1.PolicyRule
}

// realRBAC builds Kubernetes' own RBAC authorizer over the grant.
func realRBAC(g grant) *rbacauthorizer.RBACAuthorizer {
	subjects := []rbacv1.Subject{{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: oracleUser.GetName()}}
	if g.serviceAccount != "" {
		namespace, name, _ := strings.Cut(g.serviceAccount, "/")
		// A service account subject is in the core group, so it carries no
		// APIGroup of its own.
		subjects = []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: namespace, Name: name}}
	}
	if g.namespace == "" {
		role := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "granted"}, Rules: g.rules}
		binding := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "granted"},
			Subjects:   subjects,
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "granted"},
		}
		_, roles := rbacvalidation.NewTestRuleResolver(nil, nil,
			[]*rbacv1.ClusterRole{role}, []*rbacv1.ClusterRoleBinding{binding})
		// The test resolver stands in for all four getters.
		return rbacauthorizer.New(roles, roles, roles, roles)
	}
	role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "granted", Namespace: g.namespace}, Rules: g.rules}
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "granted", Namespace: g.namespace},
		Subjects:   subjects,
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "granted"},
	}
	_, roles := rbacvalidation.NewTestRuleResolver(
		[]*rbacv1.Role{role}, []*rbacv1.RoleBinding{binding}, nil, nil)
	return rbacauthorizer.New(roles, roles, roles, roles)
}

// rbacAnswer evaluates expression against Kubernetes' authorizer library backed
// by real RBAC, and reports whether it came out true.
func rbacAnswer(t *testing.T, expression string, g grant) bool {
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
	out, _, err := program.Eval(map[string]any{
		"authorizer": library.NewAuthorizerVal(oracleUser, realRBAC(g)),
	})
	if err != nil {
		t.Fatalf("evaluating %q against real RBAC: %v", expression, err)
	}
	allowed, ok := out.Value().(bool)
	if !ok {
		t.Fatalf("evaluating %q against real RBAC returned %T, want a bool", expression, out.Value())
	}
	return allowed
}

// tabForGrant writes the Authorizer tab someone would write for the grant. It
// reads the grant only -- never the check the expression will make -- so the two
// sides of the comparison stay independent.
//
// The transcription is the one the tab's shape implies: a binding that is
// cluster-wide has no namespace to key on and lands under "", a rule that names
// no resourceNames lands under "", and a resource written as "deployments/scale"
// is a subresource of "deployments". So a ClusterRoleBinding for
//
//	rules: [{apiGroups: [apps], resources: [deployments],
//	         resourceNames: [nginx], verbs: [update]}]
//
// becomes
//
//	groups:
//	  apps:
//	    resources:
//	      deployments:
//	        checks:
//	          "":              # the binding is not scoped to a namespace
//	            nginx:
//	              update:
//	                decision: allow
func tabForGrant(t *testing.T, g grant) []byte {
	t.Helper()

	tab := map[string]any{}
	for _, rule := range g.rules {
		for _, verb := range rule.Verbs {
			if verb == "*" {
				t.Fatalf("the Authorizer tab has no wildcard key, so a rule for verb %q cannot "+
					"be transcribed; write the grant out in full", verb)
			}
		}
		for _, url := range rule.NonResourceURLs {
			if strings.Contains(url, "*") {
				t.Fatalf("the Authorizer tab has no wildcard key, so a rule for %q cannot be "+
					"transcribed; write the grant out in full", url)
			}
			for _, verb := range rule.Verbs {
				nest(tab, "paths", url, "checks", verb)["decision"] = "allow"
			}
		}
		for _, group := range rule.APIGroups {
			for _, resource := range rule.Resources {
				if strings.Contains(group, "*") || strings.Contains(resource, "*") {
					t.Fatalf("the Authorizer tab has no wildcard key, so a rule for %q/%q cannot "+
						"be transcribed; write the grant out in full", group, resource)
				}
				resource, subresource, _ := strings.Cut(resource, "/")
				keys := []string{"groups", group, "resources", resource}
				if subresource != "" {
					keys = append(keys, "subresources", subresource)
				}
				keys = append(keys, "checks", g.namespace)

				names := rule.ResourceNames
				if len(names) == 0 {
					names = []string{""}
				}
				for _, name := range names {
					for _, verb := range rule.Verbs {
						nest(tab, append(keys, name, verb)...)["decision"] = "allow"
					}
				}
			}
		}
	}

	if g.serviceAccount != "" {
		namespace, name, _ := strings.Cut(g.serviceAccount, "/")
		tab = map[string]any{"serviceAccounts": map[string]any{namespace: map[string]any{name: tab}}}
	}

	out, err := yaml.Marshal(tab)
	if err != nil {
		t.Fatalf("marshalling the tab for %s: %v", g.name, err)
	}
	// The tab is only worth comparing against if it is the shape the playground
	// reads. Decoded strictly, so that a key this function misspells is caught
	// here, named and printed -- rather than as every row disagreeing about a
	// lookup that was never given anything to find.
	decoder := yaml.NewDecoder(bytes.NewReader(out))
	decoder.KnownFields(true)
	var parsed k8s.Authorizer
	if err := decoder.Decode(&parsed); err != nil {
		t.Fatalf("the tab written for %s is not one the playground can read: %v\n%s",
			g.name, err, out)
	}
	return out
}

// nest walks keys from the root of the tab, adding a map wherever there is
// none, and returns the innermost one. Rules that share a prefix -- two verbs
// on one resource, two resources in one group -- meet at the map they have in
// common instead of each writing the whole path again.
func nest(tab map[string]any, keys ...string) map[string]any {
	for _, key := range keys {
		next, ok := tab[key].(map[string]any)
		if !ok {
			next = map[string]any{}
			tab[key] = next
		}
		tab = next
	}
	return tab
}

// TestAuthorizerAgreesWithRBAC requires the fixture to answer every check the
// way the cluster the fixture describes would answer it.
//
// The interesting direction is a check narrower than the grant. A binding that
// is not scoped to a namespace answers a check in any namespace, and a rule
// naming no objects answers a check on any name, so a fixture entry has to
// answer the checks below it and not only its own.
func TestAuthorizerAgreesWithRBAC(t *testing.T) {
	updateDeployments := []rbacv1.PolicyRule{{
		APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"update"},
	}}

	grants := []grant{{
		name:  "a ClusterRoleBinding for update deployments",
		rules: updateDeployments,
	}, {
		name:      "a RoleBinding for update deployments in default",
		namespace: "default",
		rules:     updateDeployments,
	}, {
		name: "a ClusterRoleBinding for update on the deployment named nginx",
		rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"apps"}, Resources: []string{"deployments"},
			ResourceNames: []string{"nginx"}, Verbs: []string{"update"},
		}},
	}, {
		name: "a ClusterRoleBinding for update on the scale of deployments",
		rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"apps"}, Resources: []string{"deployments/scale"}, Verbs: []string{"update"},
		}},
	}, {
		name: "a ClusterRoleBinding for get on the healthz path",
		rules: []rbacv1.PolicyRule{{
			NonResourceURLs: []string{"/healthz"}, Verbs: []string{"get"},
		}},
	}, {
		// Namespaced and named at once, so the fixture entry is the most
		// specific of the four an answering walk can consider, and the one it
		// has to prefer.
		name:      "a RoleBinding in default for update on the deployment named nginx",
		namespace: "default",
		rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"apps"}, Resources: []string{"deployments"},
			ResourceNames: []string{"nginx"}, Verbs: []string{"update"},
		}},
	}, {
		// Two rules over one resource, which is what an ordinary cluster looks
		// like and what makes the tab's shared branches meet rather than each
		// rule writing its own path.
		name: "a ClusterRoleBinding for update and delete, in two rules",
		rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"update"},
		}, {
			APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"delete"},
		}},
	}, {
		// Bound to a service account rather than to the user asking, which the
		// tab keys under its own section and a policy reaches with
		// serviceAccount(). Everything under that key is the same shape as
		// above, so the transcription only has to move it.
		name:           "a ClusterRoleBinding for update deployments, bound to a service account",
		serviceAccount: "default/builder",
		rules:          updateDeployments,
	}}

	// Every expression below is asked of every grant above: the two lists are a
	// matrix, not a pairing. Most of the cells are refusals on both sides --
	// that a grant does not answer what it was never given is as much the
	// property under test as that it answers what it was.
	const deployments = `authorizer.group("apps").resource("deployments")`
	expressions := []string{
		deployments + `.check("update").allowed()`,
		// One inside the namespace a Role covers and one outside it, so a
		// cluster-wide grant has to answer both and a namespaced one only the
		// first.
		deployments + `.namespace("default").check("update").allowed()`,
		deployments + `.namespace("kube-system").check("update").allowed()`,
		// The named object and another, so a grant naming one has to answer for
		// it alone while a grant naming none answers for either.
		deployments + `.name("nginx").check("update").allowed()`,
		deployments + `.namespace("default").name("nginx").check("update").allowed()`,
		deployments + `.namespace("default").name("other").check("update").allowed()`,
		deployments + `.namespace("default").check("delete").allowed()`,
		deployments + `.subresource("scale").namespace("default").check("update").allowed()`,
		`authorizer.serviceAccount("default", "builder").group("apps").resource("deployments").` +
			`namespace("default").check("update").allowed()`,
		`authorizer.path("/healthz").check("get").allowed()`,
		// No grant below covers these, deliberately: a fixture has to decline
		// what it was never given, and one that answered yes to everything
		// would agree with a cluster on every row that matters above. They are
		// why the check below is per grant rather than per expression.
		`authorizer.group("").resource("pods").namespace("default").check("update").allowed()`,
		`authorizer.path("/healthz").check("post").allowed()`,
	}

	for _, g := range grants {
		t.Run(g.name, func(t *testing.T) {
			tab := tabForGrant(t, g)
			// Logged once for the grant rather than on each row: a parent's log
			// is printed when a child fails, and a broken grant fails several.
			t.Logf("tab:\n%s", tab)

			allowed := 0
			for _, expression := range expressions {
				t.Run(expression, func(t *testing.T) {
					clusterAllows := rbacAnswer(t, expression, g)
					if clusterAllows {
						allowed++
					}
					result := evaluate(t, expression, tab)
					if result.IsError {
						t.Fatalf("the playground could not evaluate %q: %s", expression, *result.Error)
					}
					got, ok := result.Result.(bool)
					if !ok {
						t.Fatalf("the playground answered %q with %#v, want a bool",
							expression, result.Result)
					}
					if got != clusterAllows {
						t.Errorf("%s: the playground says %v, a cluster says %v",
							expression, got, clusterAllows)
					}
				})
			}

			// A grant nothing asks about compares false with false all the way
			// down and proves nothing, which is worth failing on rather than
			// counting as coverage. A subtest rather than a check after the
			// loop, so that running one row with -run skips this instead of
			// failing it for having skipped the rows that would have passed it.
			t.Run("real RBAC allows at least one row", func(t *testing.T) {
				if allowed == 0 {
					// Only the cluster's answers are counted here, so the tab
					// and its transcription cannot be the cause.
					t.Errorf("real RBAC allowed none of the %d expressions under this grant, so "+
						"every row compared a refusal with a refusal: either no expression asks "+
						"about this grant, and one needs adding, or realRBAC did not bind it to "+
						"the subject the expressions ask as", len(expressions))
				}
			})
		})
	}
}

// TestAuthorizerPrefersTheNarrowerEntry covers the half of the lookup no
// cluster can demonstrate. RBAC has no deny -- it declines -- so a fixture that
// allows at a broad scope and refuses at a narrow one describes some other
// authorizer, and the oracle above can say nothing about it.
//
// It is the only way to write an exception, so which entry answers has to be
// the narrower one, and the answer has to be the whole entry: the reason a
// cluster gives names the binding that decided, not the scope that was asked
// about.
func TestAuthorizerPrefersTheNarrowerEntry(t *testing.T) {
	const tab = `groups:
  apps:
    resources:
      deployments:
        checks:
          "":
            "":
              update:
                decision: allow
                reason: cluster-wide
          kube-system:
            "":
              update:
                decision: deny
                reason: not-in-kube-system
`
	const check = `authorizer.group("apps").resource("deployments")`

	tests := []struct {
		name       string
		expression string
		allowed    bool
		reason     string
	}{{
		name:       "the broad entry answers the check it was written for",
		expression: check + `.check("update")`,
		allowed:    true,
		reason:     "cluster-wide",
	}, {
		// Nothing is written for this namespace, so the entry above it answers.
		name:       "the broad entry answers a namespace nothing was written for",
		expression: check + `.namespace("default").check("update")`,
		allowed:    true,
		reason:     "cluster-wide",
	}, {
		// Written for this namespace, so it answers instead of the entry above
		// it -- otherwise the exception could not be expressed at all.
		name:       "the narrow entry answers the namespace it was written for",
		expression: check + `.namespace("kube-system").check("update")`,
		allowed:    false,
		reason:     "not-in-kube-system",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed := evaluate(t, tt.expression+".allowed()", []byte(tab))
			if allowed.IsError {
				t.Fatalf("evaluating %q: %s", tt.expression, *allowed.Error)
			}
			if got := allowed.Result; got != tt.allowed {
				t.Errorf("allowed() = %v, want %v", got, tt.allowed)
			}
			reason := evaluate(t, tt.expression+".reason()", []byte(tab))
			if reason.IsError {
				t.Fatalf("evaluating the reason for %q: %s", tt.expression, *reason.Error)
			}
			if got := reason.Result; got != tt.reason {
				t.Errorf("reason() = %q, want %q -- the entry that answered is the one that "+
					"should have said why", got, tt.reason)
			}
		})
	}
}
