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

package k8s

import (
	"context"
	"errors"
	"fmt"
	"strings"

	yamlv3 "gopkg.in/yaml.v3"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

const serviceAccountPrefix = "system:serviceaccount:"

// Authorizer is the playground's authorizer tab: a canned decision tree the
// user writes by hand, keyed the way the CEL authorization library asks
// questions.
//
// It used to be a CEL value in its own right, implementing traits.Receiver and
// re-implementing authorizer.group(...).resource(...).check(...) by hand. It is
// now only *input data*: the CEL side is apiserver's real library.Authz, and
// this tree is reached through the authorizer.Authorizer interface below.
//
// That interface is the seam for a real authorizer. Anything satisfying
// k8s.io/apiserver/pkg/authorization/authorizer.Authorizer -- an RBAC
// authorizer built from Roles and RoleBindings, say -- can be swapped in at
// newPlaygroundAuthorizer without the evaluation code noticing.
type Authorizer struct {
	Paths           map[string]*PathCheck             `yaml:"paths,omitempty"`
	Groups          map[string]*GroupCheck            `yaml:"groups,omitempty"`
	ServiceAccounts map[string]map[string]*Authorizer `yaml:"serviceAccounts,omitempty"`
}

type PathCheck struct {
	Checks map[string]*Decision `yaml:"checks,omitempty"`
}

type GroupCheck struct {
	Resources map[string]*ResourceCheck `yaml:"resources,omitempty"`
}

type ResourceCheck struct {
	Subresources map[string]*ResourceCheck `yaml:"subresources,omitempty"`
	// Checks is namespace -> name -> verb -> decision. The empty string is the
	// wildcard the tab uses for "any namespace" / "any name".
	Checks map[string]map[string]map[string]*Decision `yaml:"checks,omitempty"`
}

type Decision struct {
	Error    string `yaml:"error,omitempty"`
	Decision string `yaml:"decision,omitempty"`
	Reason   string `yaml:"reason,omitempty"`
}

// playgroundAuthorizer answers authorization checks out of the tab's decision
// tree.
type playgroundAuthorizer struct {
	root *Authorizer
	// requestUser is the user the request itself is made by. Any *other*
	// service account name reaching Authorize can only have come from
	// authorizer.serviceAccount(ns, name), so it selects a nested tree.
	requestUser string
}

var _ authorizer.Authorizer = &playgroundAuthorizer{}

func newPlaygroundAuthorizer(input []byte, request *admissionv1.AdmissionRequest) (authorizer.Authorizer, error) {
	root := &Authorizer{}
	if err := yamlv3.Unmarshal(input, root); err != nil {
		return nil, fmt.Errorf("failed to decode input for the authorizer: %w", err)
	}
	return &playgroundAuthorizer{root: root, requestUser: request.UserInfo.Username}, nil
}

func (p *playgroundAuthorizer) Authorize(_ context.Context, attributes authorizer.Attributes) (authorizer.Decision, string, error) {
	tree := p.treeFor(attributes)
	if !attributes.IsResourceRequest() {
		return decide(lookupPath(tree, attributes))
	}
	return decide(lookupResource(tree, attributes))
}

// treeFor resolves authorizer.serviceAccount(namespace, name) to the nested
// tree under serviceAccounts. library.Authz implements that call by swapping
// the user info for system:serviceaccount:<ns>:<name> and reusing the same
// Authorizer, so the redirect has to happen here.
func (p *playgroundAuthorizer) treeFor(attributes authorizer.Attributes) *Authorizer {
	info := attributes.GetUser()
	if info == nil {
		return p.root
	}
	name := info.GetName()
	if name == p.requestUser || !strings.HasPrefix(name, serviceAccountPrefix) {
		return p.root
	}
	namespace, serviceAccount, ok := strings.Cut(strings.TrimPrefix(name, serviceAccountPrefix), ":")
	if !ok {
		return &Authorizer{}
	}
	if nested, ok := p.root.ServiceAccounts[namespace][serviceAccount]; ok && nested != nil {
		return nested
	}
	return &Authorizer{}
}

func lookupPath(tree *Authorizer, attributes authorizer.Attributes) *Decision {
	pathCheck, ok := tree.Paths[attributes.GetPath()]
	if !ok || pathCheck == nil {
		return nil
	}
	return pathCheck.Checks[attributes.GetVerb()]
}

func lookupResource(tree *Authorizer, attributes authorizer.Attributes) *Decision {
	groupCheck, ok := tree.Groups[attributes.GetAPIGroup()]
	if !ok || groupCheck == nil {
		return nil
	}
	resourceCheck, ok := groupCheck.Resources[attributes.GetResource()]
	if !ok || resourceCheck == nil {
		return nil
	}
	if subresource := attributes.GetSubresource(); subresource != "" {
		resourceCheck, ok = resourceCheck.Subresources[subresource]
		if !ok || resourceCheck == nil {
			return nil
		}
	}
	return resourceCheck.Checks[attributes.GetNamespace()][attributes.GetName()][attributes.GetVerb()]
}

func decide(decision *Decision) (authorizer.Decision, string, error) {
	if decision == nil {
		return authorizer.DecisionNoOpinion, "", nil
	}
	if decision.Error != "" {
		return authorizer.DecisionNoOpinion, decision.Reason, errors.New(decision.Error)
	}
	switch decision.Decision {
	case "allow":
		return authorizer.DecisionAllow, decision.Reason, nil
	case "deny":
		return authorizer.DecisionDeny, decision.Reason, nil
	default:
		return authorizer.DecisionNoOpinion, decision.Reason, nil
	}
}
