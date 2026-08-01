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
	"fmt"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

// The panel reports what every expression evaluated to, which leaves the
// reader to work out the thing they actually came for: whether the request
// gets through. These turn the results into that sentence, following the same
// rules the apiserver's validator and matcher follow.

// admissionResult is the one row the decision section holds.
func admissionResult(admitted bool, message string) []*EvalResult {
	name := "admission"
	return []*EvalResult{{Name: &name, Result: admitted, Message: message, IsError: !admitted}}
}

// matchConditionDecision reports what the matchConditions alone settle, or nil
// when they let the request through to the rest of the policy.
//
// A false condition beats an erroring one whatever order they are written in.
// The matcher evaluates every condition, collects the errors, and then walks
// the results: the first false answer returns "does not match" immediately, and
// the errors are only consulted if no answer was false
// (plugin/webhook/matchconditions/matcher.go). So a policy with one broken
// condition and one false one is skipped rather than failed, under either
// failurePolicy.
func matchConditionDecision(responses evalResponses, conditions []CelMatchConditionsInfo, failurePolicy admissionregistrationv1.FailurePolicyType) []*EvalResult {
	failed := -1
	for i, condition := range responses {
		if condition.isError() {
			if failed < 0 {
				failed = i
			}
			continue
		}
		if condition.val == nil || condition.val.Value() != true {
			return admissionResult(true, fmt.Sprintf("admitted: matchCondition %q is false, so the policy does not apply to this request", conditions[i].name))
		}
	}
	if failed < 0 {
		return nil
	}
	if failurePolicy == admissionregistrationv1.Fail {
		return admissionResult(false, fmt.Sprintf("rejected: matchCondition %q failed and failurePolicy is Fail", conditions[failed].name))
	}
	return admissionResult(true, fmt.Sprintf("admitted: matchCondition %q failed and failurePolicy is Ignore, so the policy is skipped", conditions[failed].name))
}

// policyDecision reports what a cluster would do with the request, given the
// policy's failurePolicy and what its expressions did.
func (s *evalSections) policyDecision(celInfo *CelInformation) []*EvalResult {
	result := admissionResult
	rejects := celInfo.failurePolicy == admissionregistrationv1.Fail

	if decision := matchConditionDecision(s.matchConditions, celInfo.matchConditions, celInfo.failurePolicy); decision != nil {
		return decision
	}

	for i, validation := range s.validations {
		if validation.isError() {
			if rejects {
				return result(false, fmt.Sprintf("rejected: validations[%d] failed to evaluate and failurePolicy is Fail", i))
			}
			return result(true, fmt.Sprintf("admitted: validations[%d] failed to evaluate but failurePolicy is Ignore", i))
		}
		if validation.val != nil && validation.val.Value() != true {
			return result(false, fmt.Sprintf("denied by validations[%d]: %s", i, validation.message))
		}
	}
	return result(true, "admitted: every validation passed")
}

// mutationDecision reports what a cluster would do with the request given what
// the policy's matchConditions and mutations did.
//
// A failed mutation is a rejection, not a warning: the dispatcher collects the
// error and the request is denied unless failurePolicy is Ignore. The
// playground has nothing to reject, so it applies what it can and says here
// that a cluster would not have.
func (s *evalSections) mutationDecision(celInfo *CelInformation) []*EvalResult {
	result := admissionResult

	if decision := matchConditionDecision(s.matchConditions, celInfo.matchConditions, celInfo.failurePolicy); decision != nil {
		return decision
	}

	var failed, fatal []string
	for i, mutation := range s.mutations {
		if !mutation.IsError {
			continue
		}
		failed = append(failed, fmt.Sprintf("mutations[%d]", i))
		if i < len(s.mutationFatal) && s.mutationFatal[i] {
			fatal = append(fatal, fmt.Sprintf("mutations[%d]", i))
		}
	}

	switch {
	case len(fatal) > 0:
		// A patched object the apiserver cannot decode comes back from the
		// patcher as a StatusError, and the dispatcher returns those instead of
		// collecting them, which is what takes them past the failurePolicy
		// filter. So this is an error the request cannot survive either way.
		return result(false, fmt.Sprintf("rejected: %s produced an object the apiserver cannot decode, which fails the request whatever failurePolicy says",
			strings.Join(fatal, ", ")))
	case len(failed) > 0 && celInfo.failurePolicy == admissionregistrationv1.Fail:
		return result(false, fmt.Sprintf("rejected: %s failed and failurePolicy is Fail, so the request is denied and nothing is applied",
			strings.Join(failed, ", ")))
	case len(failed) > 0:
		return result(true, fmt.Sprintf("admitted: %s failed but failurePolicy is Ignore, so those mutations are skipped and the rest still apply",
			strings.Join(failed, ", ")))
	case len(celInfo.mutations) == 0:
		return result(true, "admitted: the policy has no mutations")
	case s.finalObject == "" && s.mutationsSkipped:
		// The dispatcher skips a patcher when there is no object to patch, and
		// the request goes through untouched.
		return result(true, "admitted: the request carries no object, so no mutation ran")
	case s.diff == "":
		return result(true, "admitted: every mutation ran and left the object unchanged")
	}
	return result(true, "admitted: every mutation ran, and the object is mutated")
}

// webhookDecisions reports, per webhook, whether the apiserver would call it.
// A webhook is skipped, not failed, when a matchCondition is false; an
// erroring one is decided by that webhook's own failurePolicy.
func (s *evalSections) webhookDecisions(celInfo *CelInformation) []*EvalResult {
	decisions := make([]*EvalResult, 0, len(s.webhookMatchConditions))
	for i, conditions := range s.webhookMatchConditions {
		name := fmt.Sprintf("webhooks[%d]", i)
		rejects := true
		if i < len(celInfo.webhookFailurePolicies) {
			rejects = celInfo.webhookFailurePolicies[i] == admissionregistrationv1.Fail
		}

		called, failed, message := true, false, "called: every matchCondition is true"
		for j, condition := range conditions {
			matchCondition := celInfo.webhookMatchConditions[i][j]
			if condition.val != nil && !condition.isError() && condition.val.Value() != true {
				called, failed = false, false
				message = fmt.Sprintf("not called: matchCondition %q is false", matchCondition.name)
				break
			}
			if condition.isError() && called {
				called = false
				failed = rejects
				if rejects {
					message = fmt.Sprintf("the request is rejected without calling the webhook: matchCondition %q failed and failurePolicy is Fail", matchCondition.name)
				} else {
					message = fmt.Sprintf("not called: matchCondition %q failed and failurePolicy is Ignore", matchCondition.name)
				}
			}
		}
		decisions = append(decisions, &EvalResult{Name: &name, Result: called, Message: message, IsError: failed})
	}
	return decisions
}
