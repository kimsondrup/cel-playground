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
	"encoding/json"
	"fmt"
	"reflect"

	v1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/api/admissionregistration/v1alpha1"
	"k8s.io/api/admissionregistration/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
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

// CelMutationInfo describes a single entry of a MutatingAdmissionPolicy's
// spec.mutations. patchType is either "ApplyConfiguration" or "JSONPatch".
//
// The expression itself is deliberately not carried here: the mutations are
// compiled from policy.Spec.Mutations by the apiserver's own compiler, so a
// second copy of the expression would only be able to drift from the one that
// actually runs.
type CelMutationInfo struct {
	patchType string
}

type CelInformation struct {
	name                   string
	namespace              string
	variables              []CelVariableInfo
	validations            []CelValidationInfo
	auditAnnotations       []CelAuditAnnotationsInfo
	matchConditions        []CelMatchConditionsInfo
	webhookMatchConditions [][]CelMatchConditionsInfo
	mutations              []CelMutationInfo
	failurePolicy          string
	reinvocationPolicy     string
}

func deserializeCelInformation(data []byte) (runtime.Object, error) {
	decoder := scheme.Codecs.UniversalDeserializer()

	runtimeObject, _, err := decoder.Decode(data, nil, nil)
	if err != nil {
		return nil, err
	}

	return runtimeObject, nil
}

func extractCelInformation(input []byte) (*CelInformation, error) {
	if deser, err := deserializeCelInformation(input); err != nil {
		return nil, fmt.Errorf("failed to decode input: %w", err)
	} else {
		switch resource := deser.(type) {
		case *v1alpha1.ValidatingAdmissionPolicy:
			return extractVAPV1Alpha1CelInformation(resource), nil
		case *v1beta1.ValidatingAdmissionPolicy:
			return extractVAPV1Beta1CelInformation(resource), nil
		case *v1.ValidatingAdmissionPolicy:
			return extractVAPV1CelInformation(resource), nil
		// MutatingAdmissionPolicy is deliberately absent here: the map mode
		// deserializes it through deserializeMutatingAdmissionPolicy instead, and
		// accepting it here would make the vap and webhooks modes silently return
		// a partial result for a policy they cannot evaluate.
		case *v1beta1.ValidatingWebhookConfiguration:
			return extractVWV1Beta1CelInformation(resource), nil
		case *v1.ValidatingWebhookConfiguration:
			return extractVWV1CelInformation(resource), nil
		case *v1beta1.MutatingWebhookConfiguration:
			return extractMWV1Beta1CelInformation(resource), nil
		case *v1.MutatingWebhookConfiguration:
			return extractMWV1CelInformation(resource), nil
		default:
			deserType := reflect.TypeOf(deser)
			return nil, fmt.Errorf("unexpected input type %s", deserType.Kind())
		}
	}
}

func extractVAPV1Alpha1CelInformation(policy *v1alpha1.ValidatingAdmissionPolicy) *CelInformation {
	namespace := policy.ObjectMeta.GetNamespace()
	name := policy.ObjectMeta.GetName()

	variables := []CelVariableInfo{}
	for _, variable := range policy.Spec.Variables {
		variables = append(variables, CelVariableInfo{
			name:       variable.Name,
			expression: variable.Expression,
		})
	}

	validations := []CelValidationInfo{}
	for _, validation := range policy.Spec.Validations {

		validations = append(validations, CelValidationInfo{
			expression:        validation.Expression,
			message:           validation.Message,
			messageExpression: validation.MessageExpression,
		})
	}

	auditAnnotations := []CelAuditAnnotationsInfo{}
	for _, auditAnnotation := range policy.Spec.AuditAnnotations {
		auditAnnotations = append(auditAnnotations, CelAuditAnnotationsInfo{
			key:        auditAnnotation.Key,
			expression: auditAnnotation.ValueExpression,
		})
	}

	matchConditions := []CelMatchConditionsInfo{}
	for _, matchCondition := range policy.Spec.MatchConditions {
		matchConditions = append(matchConditions, CelMatchConditionsInfo{
			name:       matchCondition.Name,
			expression: matchCondition.Expression,
		})
	}

	return &CelInformation{
		name:             name,
		namespace:        namespace,
		variables:        variables,
		validations:      validations,
		auditAnnotations: auditAnnotations,
		matchConditions:  matchConditions,
	}
}

func extractVAPV1Beta1CelInformation(policy *v1beta1.ValidatingAdmissionPolicy) *CelInformation {
	namespace := policy.ObjectMeta.GetNamespace()
	name := policy.ObjectMeta.GetName()

	variables := []CelVariableInfo{}
	for _, variable := range policy.Spec.Variables {
		variables = append(variables, CelVariableInfo{
			name:       variable.Name,
			expression: variable.Expression,
		})
	}

	validations := []CelValidationInfo{}
	for _, validation := range policy.Spec.Validations {

		validations = append(validations, CelValidationInfo{
			expression:        validation.Expression,
			message:           validation.Message,
			messageExpression: validation.MessageExpression,
		})
	}

	auditAnnotations := []CelAuditAnnotationsInfo{}
	for _, auditAnnotation := range policy.Spec.AuditAnnotations {
		auditAnnotations = append(auditAnnotations, CelAuditAnnotationsInfo{
			key:        auditAnnotation.Key,
			expression: auditAnnotation.ValueExpression,
		})
	}

	matchConditions := []CelMatchConditionsInfo{}
	for _, matchCondition := range policy.Spec.MatchConditions {
		matchConditions = append(matchConditions, CelMatchConditionsInfo{
			name:       matchCondition.Name,
			expression: matchCondition.Expression,
		})
	}

	return &CelInformation{
		name:             name,
		namespace:        namespace,
		variables:        variables,
		validations:      validations,
		auditAnnotations: auditAnnotations,
		matchConditions:  matchConditions,
	}
}

func extractVAPV1CelInformation(policy *v1.ValidatingAdmissionPolicy) *CelInformation {
	namespace := policy.ObjectMeta.GetNamespace()
	name := policy.ObjectMeta.GetName()

	variables := []CelVariableInfo{}
	for _, variable := range policy.Spec.Variables {
		variables = append(variables, CelVariableInfo{
			name:       variable.Name,
			expression: variable.Expression,
		})
	}

	validations := []CelValidationInfo{}
	for _, validation := range policy.Spec.Validations {

		validations = append(validations, CelValidationInfo{
			expression:        validation.Expression,
			message:           validation.Message,
			messageExpression: validation.MessageExpression,
		})
	}

	auditAnnotations := []CelAuditAnnotationsInfo{}
	for _, auditAnnotation := range policy.Spec.AuditAnnotations {
		auditAnnotations = append(auditAnnotations, CelAuditAnnotationsInfo{
			key:        auditAnnotation.Key,
			expression: auditAnnotation.ValueExpression,
		})
	}

	matchConditions := []CelMatchConditionsInfo{}
	for _, matchCondition := range policy.Spec.MatchConditions {
		matchConditions = append(matchConditions, CelMatchConditionsInfo{
			name:       matchCondition.Name,
			expression: matchCondition.Expression,
		})
	}

	return &CelInformation{
		name:             name,
		namespace:        namespace,
		variables:        variables,
		validations:      validations,
		auditAnnotations: auditAnnotations,
		matchConditions:  matchConditions,
	}
}

func extractVWV1Beta1CelInformation(webhookConfig *v1beta1.ValidatingWebhookConfiguration) *CelInformation {
	webhookMatchConditions := [][]CelMatchConditionsInfo{}
	for _, webhook := range webhookConfig.Webhooks {
		matchConditions := []CelMatchConditionsInfo{}
		for _, matchCondition := range webhook.MatchConditions {
			matchConditions = append(matchConditions, CelMatchConditionsInfo{
				name:       matchCondition.Name,
				expression: matchCondition.Expression,
			})
		}
		webhookMatchConditions = append(webhookMatchConditions, matchConditions)
	}
	return &CelInformation{
		webhookMatchConditions: webhookMatchConditions,
	}
}

func extractVWV1CelInformation(webhookConfig *v1.ValidatingWebhookConfiguration) *CelInformation {
	webhookMatchConditions := [][]CelMatchConditionsInfo{}
	for _, webhook := range webhookConfig.Webhooks {
		matchConditions := []CelMatchConditionsInfo{}
		for _, matchCondition := range webhook.MatchConditions {
			matchConditions = append(matchConditions, CelMatchConditionsInfo{
				name:       matchCondition.Name,
				expression: matchCondition.Expression,
			})
		}
		webhookMatchConditions = append(webhookMatchConditions, matchConditions)
	}
	return &CelInformation{
		webhookMatchConditions: webhookMatchConditions,
	}
}

func extractMWV1Beta1CelInformation(webhookConfig *v1beta1.MutatingWebhookConfiguration) *CelInformation {
	webhookMatchConditions := [][]CelMatchConditionsInfo{}
	for _, webhook := range webhookConfig.Webhooks {
		matchConditions := []CelMatchConditionsInfo{}
		for _, matchCondition := range webhook.MatchConditions {
			matchConditions = append(matchConditions, CelMatchConditionsInfo{
				name:       matchCondition.Name,
				expression: matchCondition.Expression,
			})
		}
		webhookMatchConditions = append(webhookMatchConditions, matchConditions)
	}
	return &CelInformation{
		webhookMatchConditions: webhookMatchConditions,
	}
}

func extractMWV1CelInformation(webhookConfig *v1.MutatingWebhookConfiguration) *CelInformation {
	webhookMatchConditions := [][]CelMatchConditionsInfo{}
	for _, webhook := range webhookConfig.Webhooks {
		matchConditions := []CelMatchConditionsInfo{}
		for _, matchCondition := range webhook.MatchConditions {
			matchConditions = append(matchConditions, CelMatchConditionsInfo{
				name:       matchCondition.Name,
				expression: matchCondition.Expression,
			})
		}
		webhookMatchConditions = append(webhookMatchConditions, matchConditions)
	}
	return &CelInformation{
		webhookMatchConditions: webhookMatchConditions,
	}
}

// convertMAP normalizes an earlier served version of MutatingAdmissionPolicy
// onto the v1 shape, so everything downstream only has to understand v1.
//
// The v1alpha1, v1beta1 and v1 schemas are structurally identical in
// k8s.io/api v0.36 -- same field names, same JSON tags -- so a JSON round-trip
// is a faithful field-for-field copy and cannot silently skip a field the way
// a hand-written copy can. The "v1alpha1 policy" and "v1beta1 policy" fixtures
// are what guard that assumption if a future release breaks it.
//
// TypeMeta is cleared: the result is a v1 value, and leaving the source's
// apiVersion on it would make it claim to be something it is not. Nothing
// downstream reads it.
func convertMAP(policy runtime.Object) (*v1.MutatingAdmissionPolicy, error) {
	encoded, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to convert %T: %w", policy, err)
	}
	converted := &v1.MutatingAdmissionPolicy{}
	if err := json.Unmarshal(encoded, converted); err != nil {
		return nil, fmt.Errorf("failed to convert %T: %w", policy, err)
	}
	converted.TypeMeta = metav1.TypeMeta{}
	return converted, nil
}

func extractMAPV1CelInformation(policy *v1.MutatingAdmissionPolicy) *CelInformation {
	variables := []CelVariableInfo{}
	for _, variable := range policy.Spec.Variables {
		variables = append(variables, CelVariableInfo{
			name:       variable.Name,
			expression: variable.Expression,
		})
	}

	matchConditions := []CelMatchConditionsInfo{}
	for _, matchCondition := range policy.Spec.MatchConditions {
		matchConditions = append(matchConditions, CelMatchConditionsInfo{
			name:       matchCondition.Name,
			expression: matchCondition.Expression,
		})
	}

	mutations := []CelMutationInfo{}
	for _, mutation := range policy.Spec.Mutations {
		mutations = append(mutations, CelMutationInfo{
			patchType: string(mutation.PatchType),
		})
	}

	var failurePolicy string
	if policy.Spec.FailurePolicy != nil {
		failurePolicy = string(*policy.Spec.FailurePolicy)
	}

	return &CelInformation{
		name:               policy.ObjectMeta.GetName(),
		namespace:          policy.ObjectMeta.GetNamespace(),
		variables:          variables,
		matchConditions:    matchConditions,
		mutations:          mutations,
		failurePolicy:      failurePolicy,
		reinvocationPolicy: string(policy.Spec.ReinvocationPolicy),
	}
}
