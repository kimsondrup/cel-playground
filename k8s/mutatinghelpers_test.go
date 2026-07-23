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
	"fmt"
	"strings"
	"testing"

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
		want: "--- object\n+++ mutated\n@@ -0,0 +1,1 @@\n+a\n",
	}, {
		name: "removal down to an empty document",
		from: "a\n",
		to:   "",
		want: "--- object\n+++ mutated\n@@ -1,1 +0,0 @@\n-a\n",
	}, {
		name: "single line replaced",
		from: "a\n",
		to:   "b\n",
		want: "--- object\n+++ mutated\n@@ -1,1 +1,1 @@\n-a\n+b\n",
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

// TestUnifiedDiffHunkCountsMatchBody guards the @@ headers against drifting out
// of sync with the lines that follow them.
func TestUnifiedDiffHunkCountsMatchBody(t *testing.T) {
	from := "l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\nl11\nl12\nl13\nl14\nl15\n"
	to := "l1\nCHANGED\nl3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\nl11\nl12\nl13\nl14\nCHANGED15\n"

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
		name:        "keys are matched after trimming whitespace",
		attributes:  authorizer.AttributesRecord{ResourceRequest: true, APIGroup: " apps ", Resource: " deployments ", Verb: " update "},
		wantAllowed: authorizer.DecisionAllow,
		wantReason:  "root-allow",
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

func TestMutationAuthorizerWithoutConfig(t *testing.T) {
	adapter := &mutationAuthorizer{}
	decision, reason, err := adapter.Authorize(context.Background(), authorizer.AttributesRecord{
		ResourceRequest: true, APIGroup: "apps", Resource: "deployments", Verb: "update",
	})
	if err != nil || decision != authorizer.DecisionNoOpinion || reason != "" {
		t.Errorf("Authorize() = (%v, %q, %v), want (NoOpinion, \"\", nil)", decision, reason, err)
	}
}
