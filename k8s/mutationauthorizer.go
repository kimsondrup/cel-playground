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
	"strings"

	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

// mutationAuthorizer adapts the playground's hand-rolled Authorizer fixture
// (k8s/authorizer.go) to the authorizer.Authorizer interface that
// k8s.io/apiserver's CEL authz library expects.
//
// The mutation path reuses upstream's compiler, which binds `authorizer` and
// `authorizer.requestResource` through library.Authz() rather than through the
// playground's traits.Receiver types. Both paths therefore read the same
// Authorizer editor tab, and this adapter is what keeps their answers
// consistent.
//
// Lookup mirrors the receiver types exactly: resource checks are indexed as
// checks[namespace][name][verb], path checks as checks[verb], and a request
// made as a service account user resolves against serviceAccounts[ns][name]
// first. Keys are trimmed the way k8s/authorizer.go's getString trims them. An
// entry that is absent yields DecisionNoOpinion, which is what `allowed()`
// reports as false.
type mutationAuthorizer struct {
	config *Authorizer
}

var _ authorizer.Authorizer = &mutationAuthorizer{}

func (m *mutationAuthorizer) Authorize(_ context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
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

// configFor resolves `authorizer.serviceAccount(namespace, name)`. That
// function only swaps the request's user info, so the service account is
// recognized by its username here, exactly as a real authorizer would.
func (m *mutationAuthorizer) configFor(attr authorizer.Attributes) *Authorizer {
	if m.config == nil {
		return nil
	}
	user := attr.GetUser()
	if user == nil {
		return m.config
	}
	namespace, name, err := serviceaccount.SplitUsername(user.GetName())
	if err != nil {
		return m.config
	}
	namespacedServiceAccounts, ok := m.config.ServiceAccounts[trimKey(namespace)]
	if !ok {
		// An unknown service account gets an empty authorizer rather than the
		// requesting user's, mirroring Authorizer.Receive.
		return &Authorizer{}
	}
	serviceAccount, ok := namespacedServiceAccounts[trimKey(name)]
	if !ok || serviceAccount == nil {
		return &Authorizer{}
	}
	return serviceAccount
}

func lookupDecision(config *Authorizer, attr authorizer.Attributes) *Decision {
	if !attr.IsResourceRequest() {
		pathCheck, ok := config.Paths[trimKey(attr.GetPath())]
		if !ok || pathCheck == nil {
			return nil
		}
		return pathCheck.Checks[trimKey(attr.GetVerb())]
	}

	groupCheck, ok := config.Groups[trimKey(attr.GetAPIGroup())]
	if !ok || groupCheck == nil {
		return nil
	}
	resourceCheck, ok := groupCheck.Resources[trimKey(attr.GetResource())]
	if !ok || resourceCheck == nil {
		return nil
	}
	if subresource := trimKey(attr.GetSubresource()); subresource != "" {
		resourceCheck, ok = resourceCheck.Subresources[subresource]
		if !ok || resourceCheck == nil {
			return nil
		}
	}
	namespacedChecks, ok := resourceCheck.Checks[trimKey(attr.GetNamespace())]
	if !ok {
		return nil
	}
	namedChecks, ok := namespacedChecks[trimKey(attr.GetName())]
	if !ok {
		return nil
	}
	return namedChecks[trimKey(attr.GetVerb())]
}

// trimKey mirrors the trimming k8s/authorizer.go's getString applies to every
// argument, so a fixture key with stray whitespace resolves the same way on
// both paths.
func trimKey(key string) string {
	return strings.TrimSpace(key)
}
