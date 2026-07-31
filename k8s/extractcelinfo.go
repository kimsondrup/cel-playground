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

type CelInformation struct {
	variables              []CelVariableInfo
	validations            []CelValidationInfo
	auditAnnotations       []CelAuditAnnotationsInfo
	matchConditions        []CelMatchConditionsInfo
	webhookMatchConditions [][]CelMatchConditionsInfo
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
	"ValidatingWebhookConfiguration": {"v1", "v1beta1"},
	"MutatingWebhookConfiguration":   {"v1", "v1beta1"},
}

func extractCelInformation(input []byte) (*CelInformation, error) {
	typeMeta := metav1.TypeMeta{}
	if err := decodeTyped(input, &typeMeta, false); err != nil {
		return nil, fmt.Errorf("failed to decode input: %w", err)
	}
	if err := checkAccepted(typeMeta); err != nil {
		return nil, err
	}

	switch typeMeta.Kind {
	case "ValidatingAdmissionPolicy":
		policy := &admissionregistrationv1.ValidatingAdmissionPolicy{}
		if err := decodeTyped(input, policy, false); err != nil {
			return nil, fmt.Errorf("failed to decode input: %w", err)
		}
		return extractPolicyCelInformation(policy), nil
	case "ValidatingWebhookConfiguration":
		configuration := &admissionregistrationv1.ValidatingWebhookConfiguration{}
		if err := decodeTyped(input, configuration, false); err != nil {
			return nil, fmt.Errorf("failed to decode input: %w", err)
		}
		matchConditions := make([][]admissionregistrationv1.MatchCondition, 0, len(configuration.Webhooks))
		for _, webhook := range configuration.Webhooks {
			matchConditions = append(matchConditions, webhook.MatchConditions)
		}
		return webhookCelInformation(matchConditions), nil
	case "MutatingWebhookConfiguration":
		configuration := &admissionregistrationv1.MutatingWebhookConfiguration{}
		if err := decodeTyped(input, configuration, false); err != nil {
			return nil, fmt.Errorf("failed to decode input: %w", err)
		}
		matchConditions := make([][]admissionregistrationv1.MatchCondition, 0, len(configuration.Webhooks))
		for _, webhook := range configuration.Webhooks {
			matchConditions = append(matchConditions, webhook.MatchConditions)
		}
		return webhookCelInformation(matchConditions), nil
	default:
		return nil, unknownKindError(typeMeta.Kind)
	}
}

func webhookCelInformation(webhooks [][]admissionregistrationv1.MatchCondition) *CelInformation {
	extracted := make([][]CelMatchConditionsInfo, 0, len(webhooks))
	for _, matchConditions := range webhooks {
		extracted = append(extracted, extractMatchConditions(matchConditions))
	}
	return &CelInformation{webhookMatchConditions: extracted}
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

	return &CelInformation{
		variables:        variables,
		validations:      validations,
		auditAnnotations: auditAnnotations,
		matchConditions:  extractMatchConditions(policy.Spec.MatchConditions),
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
