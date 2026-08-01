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
	"context"
	"strings"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

// The tab that answers authorization questions must never answer one it did not
// understand. Every input here is one somebody will paste.
func TestRBACInputIsRejectedRatherThanMisread(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{{
		name: "the decision tree this tab used to take",
		input: `
paths:
groups:
  apps:
    resources:
      deployments:
        checks:
          default:
            "":
              admin:
                decision: allow
serviceAccounts:
`,
		wantErr: `apiVersion is ""`,
	}, {
		name: "a misspelled field",
		input: `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: reader
  namespace: default
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verb: ["get"]
`,
		wantErr: `unknown field "rules[0].verb"`,
	}, {
		name: "a kind the authorizer does not read",
		input: `
apiVersion: rbac.authorization.k8s.io/v1
kind: ServiceAccount
metadata:
  name: robot
`,
		wantErr: `kind is "ServiceAccount"`,
	}, {
		name: "a version no cluster has served since 1.22",
		input: `
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: Role
metadata:
  name: reader
`,
		wantErr: `apiVersion is "rbac.authorization.k8s.io/v1beta1"`,
	}, {
		name: "a good document followed by a bad one",
		input: `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: reader
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get"]
---
kind: ClusterRoleBinding
`,
		wantErr: "document 2",
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRBACAuthorizer([]byte(tt.input))
			if err == nil {
				t.Fatalf("NewRBACAuthorizer() succeeded, want an error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("NewRBACAuthorizer() error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestEmptyRBACInputAnswersEveryCheckWithNoOpinion(t *testing.T) {
	for _, input := range []string{"", "   \n", "# just a comment\n"} {
		authz, err := NewRBACAuthorizer([]byte(input))
		if err != nil {
			t.Fatalf("NewRBACAuthorizer(%q) error: %v", input, err)
		}
		decision, _, err := authz.Authorize(context.Background(), authorizer.AttributesRecord{
			User:            &user.DefaultInfo{Name: "alice"},
			Verb:            "get",
			Resource:        "pods",
			ResourceRequest: true,
		})
		if err != nil {
			t.Errorf("Authorize() error: %v", err)
		}
		if decision != authorizer.DecisionNoOpinion {
			t.Errorf("Authorize() = %v, want NoOpinion", decision)
		}
	}
}

// These are the behaviours the tab inherits by being answered with Kubernetes'
// own authorizer, rather than reimplemented. Each one was impossible to express
// in the format this replaces.
func TestRBACSemanticsComeFromKubernetes(t *testing.T) {
	const rules = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: wildcards
rules:
  - apiGroups: ["apps"]
    resources: ["*"]
    verbs: ["get"]
  - apiGroups: [""]
    resources: ["pods/log"]
    verbs: ["get"]
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["the-one"]
    verbs: ["get"]
  - nonResourceURLs: ["/healthz/*"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: everyone
subjects:
  - kind: Group
    apiGroup: rbac.authorization.k8s.io
    name: system:serviceaccounts:kube-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: wildcards
`
	authz, err := NewRBACAuthorizer([]byte(rules))
	if err != nil {
		t.Fatalf("NewRBACAuthorizer() error: %v", err)
	}

	// A ServiceAccount reaches its rules through the groups its username
	// implies, which is how authorizer.serviceAccount(ns, name) resolves.
	robot := &user.DefaultInfo{
		Name:   "system:serviceaccount:kube-system:robot",
		Groups: []string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:kube-system"},
	}
	stranger := &user.DefaultInfo{Name: "alice", Groups: []string{"system:authenticated"}}

	tests := []struct {
		name       string
		info       user.Info
		attributes authorizer.AttributesRecord
		want       authorizer.Decision
	}{{
		name:       "a resource wildcard covers a resource no rule names",
		info:       robot,
		attributes: authorizer.AttributesRecord{Verb: "get", APIGroup: "apps", Resource: "statefulsets", ResourceRequest: true},
		want:       authorizer.DecisionAllow,
	}, {
		name:       "a subresource is a path, not a nesting",
		info:       robot,
		attributes: authorizer.AttributesRecord{Verb: "get", Resource: "pods", Subresource: "log", ResourceRequest: true},
		want:       authorizer.DecisionAllow,
	}, {
		name:       "the parent resource is not covered by a subresource rule",
		info:       robot,
		attributes: authorizer.AttributesRecord{Verb: "get", Resource: "pods", ResourceRequest: true},
		want:       authorizer.DecisionNoOpinion,
	}, {
		name:       "resourceNames narrows a grant to one object",
		info:       robot,
		attributes: authorizer.AttributesRecord{Verb: "get", Resource: "secrets", Name: "the-one", ResourceRequest: true},
		want:       authorizer.DecisionAllow,
	}, {
		name:       "and excludes every other object",
		info:       robot,
		attributes: authorizer.AttributesRecord{Verb: "get", Resource: "secrets", Name: "another", ResourceRequest: true},
		want:       authorizer.DecisionNoOpinion,
	}, {
		name:       "a nonResourceURL rule matches by prefix",
		info:       robot,
		attributes: authorizer.AttributesRecord{Verb: "get", Path: "/healthz/etcd"},
		want:       authorizer.DecisionAllow,
	}, {
		name:       "somebody outside the bound group gets nothing",
		info:       stranger,
		attributes: authorizer.AttributesRecord{Verb: "get", APIGroup: "apps", Resource: "deployments", ResourceRequest: true},
		want:       authorizer.DecisionNoOpinion,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attributes := tt.attributes
			attributes.User = tt.info
			decision, reason, err := authz.Authorize(context.Background(), attributes)
			if err != nil {
				t.Fatalf("Authorize() error: %v", err)
			}
			if decision != tt.want {
				t.Errorf("Authorize() = %v (%s), want %v", decision, reason, tt.want)
			}
		})
	}
}
