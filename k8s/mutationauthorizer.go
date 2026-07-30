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
	"errors"

	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

// mutationAuthorizer adapts the playground's hand-rolled Authorizer fixture
// (k8s/authorizer.go) to the authorizer.Authorizer interface that
// k8s.io/apiserver's CEL authz library expects.
//
// The mutation path reuses upstream's compiler, which binds `authorizer` and
// `authorizer.requestResource` through library.Authz() rather than through the
// playground's traits.Receiver types. Both paths read the same Authorizer
// editor tab, and this adapter exists to give the same answers from the same
// fixture.
//
// The two are not interchangeable yet: the receiver types assign onto the
// *ResourceCheck stored in the fixture map, so state leaks between chains within
// one evaluation and an un-narrowed check() can read the request's own namespace
// and name. That is a pre-existing defect in the receiver path, not one this
// adapter introduces, and it applies inside this mode too -- matchConditions and
// spec.variables go through the receiver types, only spec.mutations come here.
//
// Lookup mirrors the receiver types: resource checks are indexed as
// checks[namespace][name][verb] with subresources nested under the resource, and
// path checks as checks[verb]. Keys are trimmed the way k8s/authorizer.go's
// getString trims them. An entry that is absent yields DecisionNoOpinion, which
// is what `allowed()` reports as false.
type mutationAuthorizer struct {
	config *Authorizer

	// requestUser is the username from the Request tab. library.Authz()'s
	// serviceAccount(namespace, name) swaps the user info it passes down and
	// leaves no other trace, so a username differing from this one is the only
	// signal that the expression asked about a service account rather than about
	// whoever is making the request.
	requestUser string

	// mutation is the 1-based position of the mutation currently being
	// evaluated, and narrowedMutations collects the ones that asked a
	// selector-narrowed question. See noteSelectors. Only ever touched from the
	// single goroutine driving one evaluation.
	mutation          int
	narrowedMutations []int
}

var _ authorizer.Authorizer = &mutationAuthorizer{}

func (m *mutationAuthorizer) Authorize(_ context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
	m.noteSelectors(attr)
	config := m.configFor(attr)
	if config == nil {
		return authorizer.DecisionNoOpinion, "", nil
	}
	decision := lookupDecision(config, attr)
	if decision == nil {
		return authorizer.DecisionNoOpinion, "", nil
	}
	if decision.Error != "" {
		// The receiver types report errored() and reason() independently, so
		// the reason is preserved alongside the error here too.
		return authorizer.DecisionNoOpinion, decision.Reason, errors.New(decision.Error)
	}
	switch decision.Decision {
	case "allow":
		return authorizer.DecisionAllow, decision.Reason, nil
	case "deny":
		return authorizer.DecisionDeny, decision.Reason, nil
	}
	return authorizer.DecisionNoOpinion, decision.Reason, nil
}

// noteSelectors records that the expression narrowed this check with
// fieldSelector() or labelSelector(). Nothing below reads the selectors: the
// Authorizer tab has no syntax for one, so the answer comes from the un-narrowed
// entry, which is the wrong answer whenever the selector is what a cluster's RBAC
// turns on. The caller turns this into a warning, because that wrongness is
// otherwise invisible -- the check returns an ordinary decision.
//
// Only the mutation path can get here at all. In a matchCondition or a variable
// the playground's own receiver types (k8s/authorizer.go) implement no such
// function and the expression fails with "no such overload"; spec.mutations go
// to the apiserver's compiler with the full base environment, where
// library.AuthzSelectors is present, so the same expression compiles and answers.
//
// A selector that does not parse counts too. Upstream records the parse failure
// on the attributes rather than rejecting the call, leaving it to the authorizer
// to act on, and ignoring it is the same silence.
func (m *mutationAuthorizer) noteSelectors(attr authorizer.Attributes) {
	fieldReqs, fieldErr := attr.GetFieldSelector()
	labelReqs, labelErr := attr.GetLabelSelector()
	if len(fieldReqs) == 0 && len(labelReqs) == 0 && fieldErr == nil && labelErr == nil {
		return
	}
	// Each mutation is evaluated twice -- once to measure its cost, once inside
	// the patcher -- and an expression may check several times, so the same
	// mutation must only be recorded once. mutation never decreases, so the last
	// entry is the only one it can repeat.
	if last := len(m.narrowedMutations) - 1; last >= 0 && m.narrowedMutations[last] == m.mutation {
		return
	}
	m.narrowedMutations = append(m.narrowedMutations, m.mutation)
}

// configFor resolves `authorizer.serviceAccount(namespace, name)`. That function
// only swaps the request's user info, so the service account is recognized by
// its username here, exactly as a real authorizer would.
//
// A username equal to the Request tab's own is not such a call, and has to keep
// the fixture root: the root section describes what the requesting user can do,
// whoever they are, and reading a service account section for it would make the
// root unreachable for every request made as a service account -- which is an
// ordinary thing to put in the Request tab, and would silently deny everything.
//
// One corner remains, and prefers the root deliberately: where the Request tab's
// user is a service account and the expression asks about that same account,
// this cannot tell the two apart and answers from the root. The receiver types
// would use the serviceAccounts section. A cluster cannot tell them apart
// either -- one user, one set of permissions -- so a fixture that gives the two
// sections different answers is describing something a cluster would not do, and
// the root is the section that governs the request actually being made.
func (m *mutationAuthorizer) configFor(attr authorizer.Attributes) *Authorizer {
	if m.config == nil {
		return nil
	}
	user := attr.GetUser()
	if user == nil || user.GetName() == m.requestUser {
		return m.config
	}
	namespace, name, err := serviceaccount.SplitUsername(user.GetName())
	if err != nil {
		return m.config
	}
	namespacedServiceAccounts, ok := m.config.ServiceAccounts[namespace]
	if !ok {
		// An unknown service account gets an empty authorizer rather than the
		// requesting user's, mirroring Authorizer.Receive.
		return &Authorizer{}
	}
	serviceAccount, ok := namespacedServiceAccounts[name]
	if !ok || serviceAccount == nil {
		return &Authorizer{}
	}
	return serviceAccount
}

func lookupDecision(config *Authorizer, attr authorizer.Attributes) *Decision {
	if !attr.IsResourceRequest() {
		pathCheck, ok := config.Paths[attr.GetPath()]
		if !ok || pathCheck == nil {
			return nil
		}
		return pathDecisionFor(pathCheck, attr.GetVerb())
	}

	groupCheck, ok := config.Groups[attr.GetAPIGroup()]
	if !ok || groupCheck == nil {
		return nil
	}
	check := narrowedCheck(groupCheck.Resources[attr.GetResource()],
		attr.GetSubresource(), attr.GetNamespace(), attr.GetName())
	return decisionFor(check, attr.GetVerb())
}
