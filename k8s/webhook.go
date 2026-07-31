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

// EvalWebhook evaluates the matchConditions of every webhook in a
// Validating/MutatingWebhookConfiguration through the apiserver's own CEL
// compiler, so each condition is type-checked the way the apiserver checks it
// when the configuration is created.
//
// A webhook has no spec.variables, and the apiserver compiles its
// matchConditions with a plain ConditionCompiler rather than the composited one
// a policy gets, so `variables` is not declared at all and naming it does not
// compile. The available variables are 'object', 'oldObject', 'request',
// 'authorizer' and 'authorizer.requestResource'; 'namespaceObject' is declared
// but left null, because the matcher passes no namespace.
func EvalWebhook(webhookInput, oldObjectInput, objectValueInput, requestInput, authorizerInput []byte) (string, error) {
	celInfo, err := extractCelInformation(webhookInput)
	if err != nil {
		return "", err
	}

	inputs, err := newEvalInputs(oldObjectInput, objectValueInput, nil, requestInput, authorizerInput)
	if err != nil {
		return "", err
	}

	scope := newMatchConditionScope(inputs)

	sections := evalSections{}
	for _, webhookMatchConditions := range celInfo.webhookMatchConditions {
		matchConditionsEval := evalResponses{}
		for _, matchCondition := range webhookMatchConditions {
			matchConditionsEval = append(matchConditionsEval,
				scope.evalExpression(matchCondition.name, &matchConditionExpression{expression: matchCondition.expression}, declsWithAuthorizer))
		}
		sections.webhookMatchConditions = append(sections.webhookMatchConditions, matchConditionsEval)
	}

	out, err := json.Marshal(sections.response())
	if err != nil {
		return "", err
	}
	return string(out), nil
}
