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
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"reflect"
	"sort"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	rbacregistry "k8s.io/kubernetes/pkg/registry/rbac/validation"
	rbacauthorizer "k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"
)

// The RBAC tab is a stream of these, `---` separated, in the group and version
// a cluster serves.
const (
	rbacGroup      = "rbac.authorization.k8s.io"
	rbacAPIVersion = rbacGroup + "/v1"
)

// rbacRules holds the RBAC tab's objects and answers the four lookups
// Kubernetes' rule resolver makes. A cluster answers them from informers; the
// playground answers them from what is in the tab, and from nothing else, so an
// unbound Role is invisible exactly as it would be.
type rbacRules struct {
	roles               map[string]*rbacv1.Role
	roleBindings        map[string][]*rbacv1.RoleBinding
	clusterRoles        map[string]*rbacv1.ClusterRole
	clusterRoleBindings []*rbacv1.ClusterRoleBinding
}

var (
	_ rbacregistry.RoleGetter               = &rbacRules{}
	_ rbacregistry.RoleBindingLister        = &rbacRules{}
	_ rbacregistry.ClusterRoleGetter        = &rbacRules{}
	_ rbacregistry.ClusterRoleBindingLister = &rbacRules{}
)

func (r *rbacRules) GetRole(_ context.Context, namespace, name string) (*rbacv1.Role, error) {
	if role, ok := r.roles[namespace+"/"+name]; ok {
		return role, nil
	}
	return nil, fmt.Errorf("no Role %q in namespace %q", name, namespace)
}

func (r *rbacRules) ListRoleBindings(_ context.Context, namespace string) ([]*rbacv1.RoleBinding, error) {
	return r.roleBindings[namespace], nil
}

func (r *rbacRules) GetClusterRole(_ context.Context, name string) (*rbacv1.ClusterRole, error) {
	if clusterRole, ok := r.clusterRoles[name]; ok {
		return clusterRole, nil
	}
	return nil, fmt.Errorf("no ClusterRole %q", name)
}

func (r *rbacRules) ListClusterRoleBindings(_ context.Context) ([]*rbacv1.ClusterRoleBinding, error) {
	return r.clusterRoleBindings, nil
}

// newRBACAuthorizer resolves the RBAC tab with Kubernetes' own RBAC authorizer,
// so `authorizer.group(...).resource(...).check(...).allowed()` is answered by
// the code that answers it on a cluster: wildcards, resourceNames, subresource
// paths, aggregated ClusterRoles, nonResourceURL prefixes and the
// system:serviceaccounts groups all behave as they do there.
//
// RBAC has no way to say no, only to stay silent. `denied()` is therefore
// always false and a check that no rule allows reports allowed()=false with no
// opinion, which is what a cluster running RBAC alone reports too.
func NewRBACAuthorizer(input []byte) (authorizer.Authorizer, error) {
	rules, err := decodeRBACInput(input)
	if err != nil {
		return nil, err
	}
	if err := rules.aggregate(); err != nil {
		return nil, err
	}
	return rbacauthorizer.New(rules, rules, rules, rules), nil
}

// aggregate fills in the rules of every ClusterRole that declares an
// aggregationRule, the way kube-controller-manager's ClusterRoleAggregation
// controller fills them in on a cluster: each selector picks ClusterRoles by
// label, their rules are concatenated in name order, and duplicates are
// dropped. The authorizer itself only ever reads `rules`, so without this an
// aggregated ClusterRole would grant nothing here and everything it aggregates
// on a cluster.
func (r *rbacRules) aggregate() error {
	names := make([]string, 0, len(r.clusterRoles))
	for name := range r.clusterRoles {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		clusterRole := r.clusterRoles[name]
		if clusterRole.AggregationRule == nil {
			continue
		}
		aggregated := []rbacv1.PolicyRule{}
		for i := range clusterRole.AggregationRule.ClusterRoleSelectors {
			selector, err := metav1.LabelSelectorAsSelector(&clusterRole.AggregationRule.ClusterRoleSelectors[i])
			if err != nil {
				return fmt.Errorf("ClusterRole %q has an unusable aggregationRule: %w", name, err)
			}
			for _, candidate := range names {
				if candidate == name {
					continue
				}
				source := r.clusterRoles[candidate]
				if !selector.Matches(labels.Set(source.Labels)) {
					continue
				}
				for _, rule := range source.Rules {
					if !containsRule(aggregated, rule) {
						aggregated = append(aggregated, rule)
					}
				}
			}
		}
		clusterRole.Rules = aggregated
	}
	return nil
}

// containsRule deduplicates the aggregated rules. A PolicyRule is five string
// slices, so reflect suffices; the one case it treats differently from the
// controller's semantic equality is a nil slice against an empty one, where the
// worst outcome is that a duplicate rule survives, and RBAC is additive.
func containsRule(rules []rbacv1.PolicyRule, rule rbacv1.PolicyRule) bool {
	for i := range rules {
		if reflect.DeepEqual(rules[i], rule) {
			return true
		}
	}
	return false
}

func decodeRBACInput(input []byte) (*rbacRules, error) {
	rules := &rbacRules{
		roles:        map[string]*rbacv1.Role{},
		roleBindings: map[string][]*rbacv1.RoleBinding{},
		clusterRoles: map[string]*rbacv1.ClusterRole{},
	}
	documents := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(input)))
	for i := 0; ; i++ {
		document, err := documents.Read()
		if err == io.EOF {
			return rules, nil
		}
		if err != nil {
			return nil, fmt.Errorf("failed to decode input for the authorizer: %w", err)
		}
		// A document that is only comments or whitespace carries no object.
		var probe any
		if err := decodeTyped(document, &probe, false); err != nil {
			return nil, fmt.Errorf("failed to decode document %d of the authorizer input: %w", i+1, err)
		}
		if probe == nil {
			continue
		}
		if err := rules.add(document); err != nil {
			return nil, fmt.Errorf("failed to decode document %d of the authorizer input: %w", i+1, err)
		}
	}
}

// add decodes one document strictly, so a misspelled field or a duplicate key
// is reported rather than dropped. A tab that says something a cluster would
// not understand is the one thing the playground must never answer quietly.
func (r *rbacRules) add(document []byte) error {
	typeMeta := metav1.TypeMeta{}
	if err := decodeTyped(document, &typeMeta, false); err != nil {
		return err
	}
	if typeMeta.APIVersion != rbacAPIVersion {
		return fmt.Errorf("apiVersion is %q; the authorizer reads %s objects", typeMeta.APIVersion, rbacAPIVersion)
	}
	switch typeMeta.Kind {
	case "Role":
		role := &rbacv1.Role{}
		if err := decodeTyped(document, role, true); err != nil {
			return err
		}
		r.roles[role.Namespace+"/"+role.Name] = role
	case "ClusterRole":
		clusterRole := &rbacv1.ClusterRole{}
		if err := decodeTyped(document, clusterRole, true); err != nil {
			return err
		}
		r.clusterRoles[clusterRole.Name] = clusterRole
	case "RoleBinding":
		roleBinding := &rbacv1.RoleBinding{}
		if err := decodeTyped(document, roleBinding, true); err != nil {
			return err
		}
		r.roleBindings[roleBinding.Namespace] = append(r.roleBindings[roleBinding.Namespace], roleBinding)
	case "ClusterRoleBinding":
		clusterRoleBinding := &rbacv1.ClusterRoleBinding{}
		if err := decodeTyped(document, clusterRoleBinding, true); err != nil {
			return err
		}
		r.clusterRoleBindings = append(r.clusterRoleBindings, clusterRoleBinding)
	default:
		return fmt.Errorf("kind is %q; the authorizer reads Role, ClusterRole, RoleBinding and ClusterRoleBinding", typeMeta.Kind)
	}
	return nil
}
