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
	"fmt"
	"slices"
	"sort"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type CelVariableInfo struct {
	name       string
	expression string
}

type CelValidationInfo struct {
	expression        string
	message           string
	messageExpression string
}

type CelAuditAnnotationsInfo struct {
	key        string
	expression string
}

type CelMatchConditionsInfo struct {
	name       string
	expression string
}

// CelMutationInfo is one entry of a MutatingAdmissionPolicy's spec.mutations.
// patchType decides which of upstream's two patchers applies the expression and
// which CEL return type it is compiled against.
type CelMutationInfo struct {
	patchType  admissionregistrationv1.PatchType
	expression string
}

type CelInformation struct {
	// hasParams follows spec.paramKind, which is what decides whether `params`
	// is declared for a policy's expressions.
	hasParams bool
	// failurePolicy decides what an expression that fails to evaluate does to
	// the request. It defaults to Fail.
	failurePolicy          admissionregistrationv1.FailurePolicyType
	webhookFailurePolicies []admissionregistrationv1.FailurePolicyType
	variables              []CelVariableInfo
	validations            []CelValidationInfo
	auditAnnotations       []CelAuditAnnotationsInfo
	matchConditions        []CelMatchConditionsInfo
	webhookMatchConditions [][]CelMatchConditionsInfo
	mutations              []CelMutationInfo
	// reinvocationPolicy and hasMatchConstraints are reported rather than acted
	// on: what they change happens outside one policy's evaluation.
	reinvocationPolicy  admissionregistrationv1.ReinvocationPolicyType
	hasMatchConstraints bool
}

const admissionregistrationGroup = "admissionregistration.k8s.io"

// acceptedVersions lists, per kind, the admissionregistration.k8s.io versions
// the playground reads.
//
// Every version of a kind declares the same CEL-carrying fields: upstream's
// generated conversions between them are pure pointer reinterpretations with no
// manual conversion anywhere in the group, and several of the shared types
// (Rule, RuleWithOperations, ScopeType, OperationType) are literal Go aliases to
// the v1 ones. So all versions decode into the v1 type and the evaluator only
// ever sees one shape. TestAcceptedVersionsAreShapedLikeV1 holds that to
// account against the real per-version types on every dependency bump.
var acceptedVersions = map[string][]string{
	"ValidatingAdmissionPolicy":      {"v1", "v1beta1", "v1alpha1"},
	"MutatingAdmissionPolicy":        {"v1", "v1beta1", "v1alpha1"},
	"ValidatingWebhookConfiguration": {"v1", "v1beta1"},
	"MutatingWebhookConfiguration":   {"v1", "v1beta1"},
}

// policyKind, mutatingPolicyKind and webhookKinds are what each mode evaluates.
// A configuration pasted into the policy editor decodes perfectly well and
// carries nothing that evaluator looks at, so without this the panel would come
// back empty and say nothing.
const (
	policyKind         = "ValidatingAdmissionPolicy"
	mutatingPolicyKind = "MutatingAdmissionPolicy"
)

var webhookKinds = []string{"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"}

func extractCelInformation(input []byte, wanted ...string) (*CelInformation, error) {
	typeMeta := metav1.TypeMeta{}
	if err := decodeTyped(input, &typeMeta, false); err != nil {
		return nil, fmt.Errorf("failed to decode input: %w", err)
	}
	if err := checkAccepted(typeMeta); err != nil {
		return nil, err
	}
	if !slices.Contains(wanted, typeMeta.Kind) {
		return nil, fmt.Errorf("this mode evaluates %s; %q belongs in the other one", strings.Join(prefixedKinds(wanted), " and "), typeMeta.Kind)
	}

	switch typeMeta.Kind {
	case "ValidatingAdmissionPolicy":
		policy := &admissionregistrationv1.ValidatingAdmissionPolicy{}
		if err := decodeTyped(input, policy, false); err != nil {
			return nil, fmt.Errorf("failed to decode input: %w", err)
		}
		return extractPolicyCelInformation(policy), nil
	case "MutatingAdmissionPolicy":
		policy := &admissionregistrationv1.MutatingAdmissionPolicy{}
		if err := decodeTyped(input, policy, false); err != nil {
			return nil, fmt.Errorf("failed to decode input: %w", err)
		}
		return extractMutatingPolicyCelInformation(policy), nil
	case "ValidatingWebhookConfiguration":
		configuration := &admissionregistrationv1.ValidatingWebhookConfiguration{}
		if err := decodeTyped(input, configuration, false); err != nil {
			return nil, fmt.Errorf("failed to decode input: %w", err)
		}
		matchConditions := make([][]admissionregistrationv1.MatchCondition, 0, len(configuration.Webhooks))
		policies := make([]admissionregistrationv1.FailurePolicyType, 0, len(configuration.Webhooks))
		for _, webhook := range configuration.Webhooks {
			matchConditions = append(matchConditions, webhook.MatchConditions)
			policies = append(policies, webhookFailurePolicy(webhook.FailurePolicy))
		}
		return webhookCelInformation(matchConditions, policies), nil
	case "MutatingWebhookConfiguration":
		configuration := &admissionregistrationv1.MutatingWebhookConfiguration{}
		if err := decodeTyped(input, configuration, false); err != nil {
			return nil, fmt.Errorf("failed to decode input: %w", err)
		}
		matchConditions := make([][]admissionregistrationv1.MatchCondition, 0, len(configuration.Webhooks))
		policies := make([]admissionregistrationv1.FailurePolicyType, 0, len(configuration.Webhooks))
		for _, webhook := range configuration.Webhooks {
			matchConditions = append(matchConditions, webhook.MatchConditions)
			policies = append(policies, webhookFailurePolicy(webhook.FailurePolicy))
		}
		return webhookCelInformation(matchConditions, policies), nil
	default:
		return nil, unknownKindError(typeMeta.Kind)
	}
}

func webhookCelInformation(webhooks [][]admissionregistrationv1.MatchCondition, policies []admissionregistrationv1.FailurePolicyType) *CelInformation {
	extracted := make([][]CelMatchConditionsInfo, 0, len(webhooks))
	for _, matchConditions := range webhooks {
		extracted = append(extracted, extractMatchConditions(matchConditions))
	}
	return &CelInformation{webhookMatchConditions: extracted, webhookFailurePolicies: policies}
}

func webhookFailurePolicy(policy *admissionregistrationv1.FailurePolicyType) admissionregistrationv1.FailurePolicyType {
	if policy == nil {
		return admissionregistrationv1.Fail
	}
	return *policy
}

// checkAccepted rejects anything the playground cannot evaluate, naming what it
// can, because "apiVersion: admissionregistration.k8s.io/v2" and a misspelled
// kind are the two mistakes that reach this function.
func checkAccepted(typeMeta metav1.TypeMeta) error {
	if typeMeta.Kind == "" {
		return fmt.Errorf("no kind is set; expected one of %s", strings.Join(acceptedKinds(), ", "))
	}
	versions, ok := acceptedVersions[typeMeta.Kind]
	if !ok {
		return unknownKindError(typeMeta.Kind)
	}
	group, version, _ := strings.Cut(typeMeta.APIVersion, "/")
	if group != admissionregistrationGroup {
		return fmt.Errorf("cannot evaluate apiVersion %q for kind %q; expected group %s", typeMeta.APIVersion, typeMeta.Kind, admissionregistrationGroup)
	}
	for _, accepted := range versions {
		if version == accepted {
			return nil
		}
	}
	return fmt.Errorf("cannot evaluate apiVersion %q for kind %q; expected one of %s", typeMeta.APIVersion, typeMeta.Kind, strings.Join(prefixed(admissionregistrationGroup+"/", versions), ", "))
}

func prefixedKinds(kinds []string) []string {
	out := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		out = append(out, "a "+kind)
	}
	return out
}

func unknownKindError(kind string) error {
	return fmt.Errorf("cannot evaluate kind %q; expected one of %s", kind, strings.Join(acceptedKinds(), ", "))
}

func acceptedKinds() []string {
	kinds := make([]string, 0, len(acceptedVersions))
	for kind := range acceptedVersions {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	return kinds
}

func prefixed(prefix string, values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, prefix+value)
	}
	return out
}

func extractPolicyCelInformation(policy *admissionregistrationv1.ValidatingAdmissionPolicy) *CelInformation {
	variables := make([]CelVariableInfo, 0, len(policy.Spec.Variables))
	for _, variable := range policy.Spec.Variables {
		variables = append(variables, CelVariableInfo{
			name:       variable.Name,
			expression: variable.Expression,
		})
	}

	validations := make([]CelValidationInfo, 0, len(policy.Spec.Validations))
	for _, validation := range policy.Spec.Validations {
		validations = append(validations, CelValidationInfo{
			expression:        validation.Expression,
			message:           validation.Message,
			messageExpression: validation.MessageExpression,
		})
	}

	auditAnnotations := make([]CelAuditAnnotationsInfo, 0, len(policy.Spec.AuditAnnotations))
	for _, auditAnnotation := range policy.Spec.AuditAnnotations {
		auditAnnotations = append(auditAnnotations, CelAuditAnnotationsInfo{
			key:        auditAnnotation.Key,
			expression: auditAnnotation.ValueExpression,
		})
	}

	failurePolicy := admissionregistrationv1.Fail
	if policy.Spec.FailurePolicy != nil {
		failurePolicy = *policy.Spec.FailurePolicy
	}

	return &CelInformation{
		hasParams:        policy.Spec.ParamKind != nil,
		failurePolicy:    failurePolicy,
		variables:        variables,
		validations:      validations,
		auditAnnotations: auditAnnotations,
		matchConditions:  extractMatchConditions(policy.Spec.MatchConditions),
	}
}

func extractMutatingPolicyCelInformation(policy *admissionregistrationv1.MutatingAdmissionPolicy) *CelInformation {
	variables := make([]CelVariableInfo, 0, len(policy.Spec.Variables))
	for _, variable := range policy.Spec.Variables {
		variables = append(variables, CelVariableInfo{
			name:       variable.Name,
			expression: variable.Expression,
		})
	}

	// A mutation whose patch type names a body it does not carry keeps its
	// place in the list with an empty expression, so the panel numbers the
	// mutations the way the policy does and the entry reports what is wrong
	// with it rather than vanishing.
	mutations := make([]CelMutationInfo, 0, len(policy.Spec.Mutations))
	for _, mutation := range policy.Spec.Mutations {
		info := CelMutationInfo{patchType: mutation.PatchType}
		switch {
		case mutation.PatchType == admissionregistrationv1.PatchTypeApplyConfiguration && mutation.ApplyConfiguration != nil:
			info.expression = mutation.ApplyConfiguration.Expression
		case mutation.PatchType == admissionregistrationv1.PatchTypeJSONPatch && mutation.JSONPatch != nil:
			info.expression = mutation.JSONPatch.Expression
		}
		mutations = append(mutations, info)
	}

	failurePolicy := admissionregistrationv1.Fail
	if policy.Spec.FailurePolicy != nil {
		failurePolicy = *policy.Spec.FailurePolicy
	}

	return &CelInformation{
		hasParams:           policy.Spec.ParamKind != nil,
		failurePolicy:       failurePolicy,
		reinvocationPolicy:  policy.Spec.ReinvocationPolicy,
		hasMatchConstraints: policy.Spec.MatchConstraints != nil,
		variables:           variables,
		mutations:           mutations,
		matchConditions:     extractMatchConditions(policy.Spec.MatchConditions),
	}
}

func extractMatchConditions(matchConditions []admissionregistrationv1.MatchCondition) []CelMatchConditionsInfo {
	extracted := make([]CelMatchConditionsInfo, 0, len(matchConditions))
	for _, matchCondition := range matchConditions {
		extracted = append(extracted, CelMatchConditionsInfo{
			name:       matchCondition.Name,
			expression: matchCondition.Expression,
		})
	}
	return extracted
}
