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
	"reflect"

	v1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/api/admissionregistration/v1alpha1"
	"k8s.io/api/admissionregistration/v1beta1"
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
// spec.mutations. patchType is either "ApplyConfiguration" or "JSONPatch" and
// expression is the corresponding applyConfiguration.expression /
// jsonPatch.expression.
type CelMutationInfo struct {
	patchType  string
	expression string
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

// convertMAPV1Alpha1 and convertMAPV1Beta1 normalize the earlier served
// versions of MutatingAdmissionPolicy onto the v1 shape. The three schemas are
// structurally identical in k8s.io/api v0.36, so the conversion is a
// field-for-field copy of the parts the playground evaluates; everything
// downstream then only has to understand v1.
func convertMAPV1Alpha1(policy *v1alpha1.MutatingAdmissionPolicy) *v1.MutatingAdmissionPolicy {
	converted := &v1.MutatingAdmissionPolicy{ObjectMeta: policy.ObjectMeta}
	converted.Spec.ReinvocationPolicy = v1.ReinvocationPolicyType(policy.Spec.ReinvocationPolicy)
	if policy.Spec.FailurePolicy != nil {
		failurePolicy := v1.FailurePolicyType(*policy.Spec.FailurePolicy)
		converted.Spec.FailurePolicy = &failurePolicy
	}
	if policy.Spec.ParamKind != nil {
		converted.Spec.ParamKind = &v1.ParamKind{
			APIVersion: policy.Spec.ParamKind.APIVersion,
			Kind:       policy.Spec.ParamKind.Kind,
		}
	}
	for _, variable := range policy.Spec.Variables {
		converted.Spec.Variables = append(converted.Spec.Variables, v1.Variable{
			Name:       variable.Name,
			Expression: variable.Expression,
		})
	}
	for _, matchCondition := range policy.Spec.MatchConditions {
		converted.Spec.MatchConditions = append(converted.Spec.MatchConditions, v1.MatchCondition{
			Name:       matchCondition.Name,
			Expression: matchCondition.Expression,
		})
	}
	for _, mutation := range policy.Spec.Mutations {
		next := v1.Mutation{PatchType: v1.PatchType(mutation.PatchType)}
		if mutation.ApplyConfiguration != nil {
			next.ApplyConfiguration = &v1.ApplyConfiguration{Expression: mutation.ApplyConfiguration.Expression}
		}
		if mutation.JSONPatch != nil {
			next.JSONPatch = &v1.JSONPatch{Expression: mutation.JSONPatch.Expression}
		}
		converted.Spec.Mutations = append(converted.Spec.Mutations, next)
	}
	return converted
}

func convertMAPV1Beta1(policy *v1beta1.MutatingAdmissionPolicy) *v1.MutatingAdmissionPolicy {
	converted := &v1.MutatingAdmissionPolicy{ObjectMeta: policy.ObjectMeta}
	converted.Spec.ReinvocationPolicy = v1.ReinvocationPolicyType(policy.Spec.ReinvocationPolicy)
	if policy.Spec.FailurePolicy != nil {
		failurePolicy := v1.FailurePolicyType(*policy.Spec.FailurePolicy)
		converted.Spec.FailurePolicy = &failurePolicy
	}
	if policy.Spec.ParamKind != nil {
		converted.Spec.ParamKind = &v1.ParamKind{
			APIVersion: policy.Spec.ParamKind.APIVersion,
			Kind:       policy.Spec.ParamKind.Kind,
		}
	}
	for _, variable := range policy.Spec.Variables {
		converted.Spec.Variables = append(converted.Spec.Variables, v1.Variable{
			Name:       variable.Name,
			Expression: variable.Expression,
		})
	}
	for _, matchCondition := range policy.Spec.MatchConditions {
		converted.Spec.MatchConditions = append(converted.Spec.MatchConditions, v1.MatchCondition{
			Name:       matchCondition.Name,
			Expression: matchCondition.Expression,
		})
	}
	for _, mutation := range policy.Spec.Mutations {
		next := v1.Mutation{PatchType: v1.PatchType(mutation.PatchType)}
		if mutation.ApplyConfiguration != nil {
			next.ApplyConfiguration = &v1.ApplyConfiguration{Expression: mutation.ApplyConfiguration.Expression}
		}
		if mutation.JSONPatch != nil {
			next.JSONPatch = &v1.JSONPatch{Expression: mutation.JSONPatch.Expression}
		}
		converted.Spec.Mutations = append(converted.Spec.Mutations, next)
	}
	return converted
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
		var expression string
		switch {
		case mutation.ApplyConfiguration != nil:
			expression = mutation.ApplyConfiguration.Expression
		case mutation.JSONPatch != nil:
			expression = mutation.JSONPatch.Expression
		}
		mutations = append(mutations, CelMutationInfo{
			patchType:  string(mutation.PatchType),
			expression: expression,
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
