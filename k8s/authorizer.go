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
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

var (
	AuthorizerType    = cel.OpaqueType("playground.k8s.Authorizer")
	PathCheckType     = cel.OpaqueType("playground.k8s.PathCheck")
	GroupCheckType    = cel.OpaqueType("playground.k8s.GroupCheck")
	ResourceCheckType = cel.OpaqueType("playground.k8s.ResourceCheck")
	DecisionType      = cel.OpaqueType("playground.k8s.Decision")
)

var _ traits.Receiver = &Authorizer{}

type Authorizer struct {
	receiverOnlyObjectVal
	Paths           map[string]*PathCheck             `yaml:"paths,omitempty"`
	Groups          map[string]*GroupCheck            `yaml:"groups,omitempty"`
	ServiceAccounts map[string]map[string]*Authorizer `yaml:"serviceAccounts,omitempty"`
}

func (a *Authorizer) Receive(function string, overload string, args []ref.Val) ref.Val {
	switch len(args) {
	case 1:
		switch function {
		case "path":
			if path, ok := getString(args[0].Value()); ok {
				if len(path) == 0 {
					return types.NewErr("path must not be empty")
				} else if a.Paths != nil {
					if pathCheck, ok := a.Paths[path]; ok && pathCheck != nil {
						initReceiver(&pathCheck.receiverOnlyObjectVal, PathCheckType)
						return pathCheck
					}
				}
				pathCheck := &PathCheck{}
				initReceiver(&pathCheck.receiverOnlyObjectVal, PathCheckType)
				return pathCheck
			}
		case "group":
			if group, ok := getString(args[0].Value()); ok {
				if a.Groups != nil {
					if groupCheck, ok := a.Groups[group]; ok && groupCheck != nil {
						initReceiver(&groupCheck.receiverOnlyObjectVal, GroupCheckType)
						return groupCheck
					}
				}
				groupCheck := &GroupCheck{}
				initReceiver(&groupCheck.receiverOnlyObjectVal, GroupCheckType)
				return groupCheck
			}
		}
	case 2:
		switch function {
		case "serviceAccount":
			// TODO check the namespace and name to see if they are valid
			if namespace, ok := getString(args[0].Value()); ok {
				if name, ok := getString(args[1].Value()); ok {
					if a.ServiceAccounts != nil {
						if namespacedServiceAccounts, ok := a.ServiceAccounts[namespace]; ok {
							if authorizer, ok := namespacedServiceAccounts[name]; ok && authorizer != nil {
								initReceiver(&authorizer.receiverOnlyObjectVal, AuthorizerType)
								return authorizer
							}
						}
					}
					authorizer := &Authorizer{}
					initReceiver(&authorizer.receiverOnlyObjectVal, AuthorizerType)
					return authorizer
				}
			}
		}
	}
	return types.NewErr("Error processing authorizer: %s, %s, %v", function, overload, args)

	// return types.NoSuchOverloadErr()
}

type PathCheck struct {
	receiverOnlyObjectVal
	Checks map[string]*Decision `yaml:"checks,omitempty"`
}

var _ traits.Receiver = &PathCheck{}

func (p *PathCheck) Receive(function string, overload string, args []ref.Val) ref.Val {
	if function == "check" && len(args) == 1 {
		verb, ok := getString(args[0].Value())
		if !ok {
			return types.NoSuchOverloadErr()
		}
		if len(verb) == 0 {
			return types.NewErr("must specify check")
		}
		return decisionValue(pathDecisionFor(p, verb))
	}
	return types.NoSuchOverloadErr()
}

type GroupCheck struct {
	receiverOnlyObjectVal
	Resources map[string]*ResourceCheck `json:"resources,omitempty"`
}

var _ traits.Receiver = &GroupCheck{}

func (g *GroupCheck) Receive(function string, overload string, args []ref.Val) ref.Val {
	if function == "resource" && len(args) == 1 {
		if resource, ok := getString(args[0].Value()); ok {
			if len(resource) == 0 {
				// An empty resource has no answer, so it errors rather than
				// answering, as groupCheckResource in
				// k8s.io/apiserver/pkg/cel/library does.
				return types.NewErr("resource must not be empty")
			}
			return narrowedCheck(g.Resources[resource], "", "", "")
		}
	}
	return types.NoSuchOverloadErr()
}

var _ traits.Receiver = &ResourceCheck{}

type ResourceCheck struct {
	receiverOnlyObjectVal
	subresource string
	namespace   string
	name        string

	Subresources map[string]*ResourceCheck                  `yaml:"subresources,omitempty"`
	Checks       map[string]map[string]map[string]*Decision `yaml:"checks,omitempty"`
}

// Receive answers a check, or returns a copy of it narrowed by one more scoping
// call.
//
// subresource(), namespace() and name() each replace what an earlier call in the
// same chain set. An empty argument clears it: subresource() and name() go back to
// unset, and namespace("") is the cluster scope, not every namespace.
func (r *ResourceCheck) Receive(function string, overload string, args []ref.Val) ref.Val {
	if len(args) == 1 {
		switch function {
		case "subresource":
			if subresource, ok := getString(args[0].Value()); ok {
				return narrowedCheck(r, subresource, r.namespace, r.name)
			}
		case "namespace":
			if namespace, ok := getString(args[0].Value()); ok {
				return narrowedCheck(r, r.subresource, namespace, r.name)
			}
		case "name":
			if name, ok := getString(args[0].Value()); ok {
				return narrowedCheck(r, r.subresource, r.namespace, name)
			}
		case "check":
			verb, ok := getString(args[0].Value())
			if !ok {
				return types.NoSuchOverloadErr()
			}
			if len(verb) == 0 {
				return types.NewErr("must specify check")
			}
			return decisionValue(decisionFor(r, verb))
		}
	}
	return types.NoSuchOverloadErr()
}

// narrowedCheck returns a copy of an entry from the fixture, scoped to a
// subresource, a namespace and a name. Subresources and Checks stay the fixture's
// own maps, shared by every copy and never written to; the copy holds only the
// scoping.
//
// The copy is what keeps one expression's scoping out of the next one's. A single
// ResourceCheck value can be reached by more than one expression: the value bound
// as authorizer.requestResource is built once for the whole policy, and a
// composited variable holding a check is evaluated once and its value reused.
// Narrowing in place would scope those for every later expression too.
//
// A nil entry is a resource the fixture does not mention, or a key written with no
// body under it. It has no checks either way, so every lookup on it answers no
// opinion.
func narrowedCheck(entry *ResourceCheck, subresource, namespace, name string) *ResourceCheck {
	narrowed := &ResourceCheck{
		subresource: subresource,
		namespace:   namespace,
		name:        name,
	}
	if entry != nil {
		narrowed.Subresources = entry.Subresources
		narrowed.Checks = entry.Checks
	}
	initReceiver(&narrowed.receiverOnlyObjectVal, ResourceCheckType)
	return narrowed
}

// decisionFor answers what the fixture says for a verb, given a check already
// scoped to a group and a resource. A nil result means the fixture has no entry
// for that combination: no opinion, not a denial.
func decisionFor(check *ResourceCheck, verb string) *Decision {
	checks := check.Checks
	if check.subresource != "" {
		// A subresource keeps its checks in its own entry under the resource.
		entry, ok := check.Subresources[check.subresource]
		if !ok || entry == nil {
			return nil
		}
		checks = entry.Checks
	}
	namespacedChecks, ok := checks[check.namespace]
	if !ok {
		return nil
	}
	namedChecks, ok := namespacedChecks[check.name]
	if !ok {
		return nil
	}
	return namedChecks[verb]
}

// pathDecisionFor answers what the fixture says for a non-resource path check. A
// nil result is no opinion, as in decisionFor.
func pathDecisionFor(check *PathCheck, verb string) *Decision {
	return check.Checks[verb]
}

// decisionValue wraps a looked-up decision as the CEL value the expression sees.
// No opinion becomes an empty Decision, so allowed() is false and reason() is
// empty rather than the expression erroring.
//
// The value is a copy, so that initialising its CEL type does not write into the
// fixture's own decision.
func decisionValue(decision *Decision) ref.Val {
	var value Decision
	if decision != nil {
		value = *decision
	}
	initReceiver(&value.receiverOnlyObjectVal, DecisionType)
	return &value
}

type Decision struct {
	receiverOnlyObjectVal
	Error    string `yaml:"error,omitempty"`
	Decision string `yaml:"decision,omitempty"`
	Reason   string `yaml:"reason,omitempty"`
}

var _ traits.Receiver = &Decision{}

func (d *Decision) Receive(function string, overload string, args []ref.Val) ref.Val {
	if len(args) == 0 {
		switch function {
		case "errored":
			return types.Bool(d.Error != "")
		case "error":
			return types.String(d.Error)
		case "allowed":
			return types.Bool(d.Decision == "allow")
		case "reason":
			return types.String(d.Reason)
		}
	}
	return types.NoSuchOverloadErr()
}

func initReceiver(receiver *receiverOnlyObjectVal, varType *types.Type) {
	if receiver.typeValue == nil {
		*receiver = receiverOnlyVal(varType)
	}
}

func getString(val any) (string, bool) {
	if strptr, ok := val.(*string); ok {
		if strptr == nil {
			return "", false
		} else {
			return strings.TrimSpace(*strptr), ok
		}
	} else if str, ok := val.(string); ok {
		return strings.TrimSpace(str), ok
	} else {
		return "", false
	}
}

func getValOrEmpty(val any) string {
	if str, ok := getString(val); ok {
		return str
	} else {
		return ""
	}
}

// getAuthorizerRequestResource builds the authorizer.requestResource value the
// CEL environment binds, from the Request tab.
func getAuthorizerRequestResource(authorizer *Authorizer, request map[string]any) (*ResourceCheck, error) {
	if authorizer == nil || request == nil {
		return nil, nil
	}
	resourceMap, _ := request["resource"].(map[string]any)
	group := getValOrEmpty(resourceMap["group"])
	resource := getValOrEmpty(resourceMap["resource"])
	if resource == "" {
		// The Request tab names no resource to build the check from. A cluster
		// always binds requestResource, so bind a check with nothing under it,
		// which answers no opinion. Asking the fixture for the empty resource
		// would instead return an error from here and abandon the whole
		// evaluation, including for policies that never read the authorizer.
		return narrowedCheck(nil, "", "", ""), nil
	}
	name := getValOrEmpty(request["name"])
	namespace := getValOrEmpty(request["namespace"])

	receivers := [][2]string{
		{"group", group},
		{"resource", resource},
		{"namespace", namespace},
		{"name", name},
	}

	var receiver traits.Receiver = authorizer
	for _, receiverFunction := range receivers {
		val := receiver.Receive(receiverFunction[0], "", []ref.Val{types.String(receiverFunction[1])})
		if err, ok := val.(*types.Err); ok {
			return nil, err
		}
		receiver = val.(traits.Receiver)
	}
	return receiver.(*ResourceCheck), nil
}
