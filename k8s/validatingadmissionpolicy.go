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
)

// EvalValidatingAdmissionPolicy evaluates a ValidatingAdmissionPolicy against
// the playground's inputs using the apiserver's own CEL compiler
// (k8s.io/apiserver/pkg/admission/plugin/cel), so an expression is compiled and
// type-checked exactly as it would be when the policy is created on a cluster.
//
// The CEL variables available follow apiserver's environment:
//
//	'object'          - the object from the incoming request; null for DELETE.
//	'oldObject'       - the existing object; null for CREATE.
//	'request'         - the AdmissionRequest attributes.
//	'params'          - not exposed yet; the playground has no params tab.
//	'namespaceObject' - the namespace of the incoming object; null when cluster-scoped.
//	'variables'       - spec.variables, lazily evaluated, e.g. variables.foo.
//	'authorizer'      - a CEL Authorizer backed by the authorizer tab.
//	'authorizer.requestResource' - the same authorizer preconfigured with the request resource.
//
// The matchCondition semantics are unchanged:
//  1. If ANY matchCondition evaluates to FALSE, the policy is skipped.
//  2. If ALL matchConditions evaluate to TRUE, the policy is evaluated.
//  3. If any matchCondition evaluates to an error (but none are FALSE):
//     - if failurePolicy=Fail, the request is rejected;
//     - if failurePolicy=Ignore, the policy is skipped.
//
// matchConditions and validations are compiled in separate scopes, as they are
// on a cluster: a variable read from a matchCondition is evaluated (and charged)
// independently of the same variable read from a validation, which is why the
// result panel reports two variable lists.
func EvalValidatingAdmissionPolicy(policyInput, oldObjectInput, objectValueInput, namespaceInput, requestInput, authorizerInput []byte) (string, error) {
	celInfo, err := extractCelInformation(policyInput)
	if err != nil {
		return "", err
	}

	inputs, err := newEvalInputs(oldObjectInput, objectValueInput, namespaceInput, requestInput, authorizerInput)
	if err != nil {
		return "", err
	}

	matchConditionsEvaluator, err := newCelEvaluator(inputs, celInfo.variables)
	if err != nil {
		return "", err
	}

	matchConditions := true
	matchConditionsEvals := evalResponses{}
	for _, matchCondition := range celInfo.matchConditions {
		response := matchConditionsEvaluator.evalExpression(matchCondition.name, &matchConditionExpression{expression: matchCondition.expression})
		// An erroring matchCondition is left to the failurePolicy; only an
		// unambiguous false skips the policy.
		if !response.isError() && response.val != nil && response.val.Value() != true {
			matchConditions = false
		}
		matchConditionsEvals = append(matchConditionsEvals, response)
	}

	validationEvals := evalResponses{}
	auditAnnotationEvals := evalResponses{}
	var validationVariableNames []string
	validationVariables := evalResults{}

	// run validations only if matchConditions pass
	if matchConditions {
		validationEvaluator, err := newCelEvaluator(inputs, celInfo.variables)
		if err != nil {
			return "", err
		}
		validationVariableNames = validationEvaluator.variableNames
		validationVariables = validationEvaluator.variableResults

		validationResult := true
		for _, validation := range celInfo.validations {
			response := validationEvaluator.evalExpression("", &validationExpression{expression: validation.expression})
			if response.val == nil || response.val.Value() != false {
				validationEvals = append(validationEvals, response)
				continue
			}
			// The validation failed: attach its message. A literal message wins
			// over messageExpression, matching the apiserver.
			validationResult = false
			switch {
			case validation.message != "":
				response.message = validation.message
			case validation.messageExpression != "":
				messageResponse := validationEvaluator.evalExpression("", &messageExpression{expression: validation.messageExpression})
				if messageResponse.isError() {
					response = messageResponse
				} else {
					response.messageVal = messageResponse.val
					response.addCost(messageResponse.cost)
				}
			}
			validationEvals = append(validationEvals, response)
		}

		if validationResult {
			for _, auditAnnotation := range celInfo.auditAnnotations {
				response := validationEvaluator.evalExpression(auditAnnotation.key, &auditAnnotationExpression{expression: auditAnnotation.expression})
				if !response.isError() {
					response.messageVal, response.val = response.val, nil
				}
				auditAnnotationEvals = append(auditAnnotationEvals, response)
			}
		}
	}

	response := generateEvalResponse(
		matchConditionsEvaluator.variableNames, matchConditionsEvaluator.variableResults, matchConditionsEvals,
		validationVariableNames, validationVariables, validationEvals,
		auditAnnotationEvals, nil)

	out, err := json.Marshal(response)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
