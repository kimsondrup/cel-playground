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
	"strings"

	celconfig "k8s.io/apiserver/pkg/apis/cel"
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
//	'authorizer'      - a CEL Authorizer backed by the RBAC tab.
//	'authorizer.requestResource' - the same authorizer preconfigured with the request resource.
//
// Not every expression sees all of them. A cluster evaluates a policy in four
// batches and binds each batch differently, so the playground does too:
//
//	matchConditions     no namespaceObject; authorizer bound
//	validations         namespaceObject; authorizer bound
//	messageExpressions  namespaceObject; authorizer not declared at all
//	auditAnnotations    namespaceObject; authorizer declared but NOT bound
//
// Each batch also gets its own binding of `variables`, so a variable read from
// two batches is evaluated -- and charged -- twice, as it is on a cluster.
// matchConditions are the exception: `variables` is not declared there at all,
// because the apiserver refuses to store a policy whose matchConditions name
// it.
//
// matchCondition semantics:
//  1. If ANY matchCondition evaluates to false, the policy is skipped.
//  2. If ALL matchConditions evaluate to true, the policy is evaluated.
//  3. If any matchCondition errors (and none are false), the policy is skipped
//     too: failurePolicy=Fail rejects the request and failurePolicy=Ignore
//     ignores the policy, and neither runs the validations.
func EvalValidatingAdmissionPolicy(policyInput, oldObjectInput, objectValueInput, namespaceInput, requestInput, authorizerInput []byte) (string, error) {
	celInfo, err := extractCelInformation(policyInput)
	if err != nil {
		return "", err
	}

	inputs, err := newEvalInputs(oldObjectInput, objectValueInput, namespaceInput, requestInput, authorizerInput)
	if err != nil {
		return "", err
	}

	compiler, err := newPolicyCompiler(celInfo.variables)
	if err != nil {
		return "", err
	}

	sections := evalSections{}
	matched := true
	if len(celInfo.matchConditions) > 0 {
		scope := newMatchConditionScope(inputs)
		sections.matchConditionScope = scope
		for _, matchCondition := range celInfo.matchConditions {
			response := scope.evalExpression(matchCondition.name, &matchConditionExpression{expression: matchCondition.expression}, declsWithAuthorizer)
			if response.isError() || response.val == nil || response.val.Value() != true {
				matched = false
			}
			sections.matchConditions = append(sections.matchConditions, response)
		}
	}

	if matched {
		sections.evaluatePolicy(compiler, inputs, celInfo)
	}

	out, err := json.Marshal(sections.response())
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// evaluatePolicy runs the three batches a matched policy evaluates: the
// validations, every messageExpression, and every audit annotation. The last
// two run whatever the validations decided -- a cluster evaluates them
// unconditionally and charges for them -- even though a messageExpression's
// result is only read when its validation failed.
func (s *evalSections) evaluatePolicy(compiler *policyCompiler, inputs *evalInputs, celInfo *CelInformation) {
	validationScope := compiler.newScope(inputs, validationBindings)
	s.validationScope = validationScope
	for _, validation := range celInfo.validations {
		s.validations = append(s.validations, validationScope.evalExpression("", &validationExpression{expression: validation.expression}, declsWithAuthorizer))
	}

	messages := s.evaluateMessageExpressions(compiler, inputs, celInfo)

	for i, validation := range celInfo.validations {
		response := s.validations[i]
		if response.isError() || response.val == nil || response.val.Value() == true {
			continue
		}
		response.message = resolveMessage(validation, messages[i])
	}

	if len(celInfo.auditAnnotations) > 0 {
		auditScope := compiler.newScope(inputs, auditAnnotationBindings)
		s.auditAnnotationScope = auditScope
		for _, auditAnnotation := range celInfo.auditAnnotations {
			response := auditScope.evalExpression(auditAnnotation.key, &auditAnnotationExpression{expression: auditAnnotation.expression}, declsWithAuthorizer)
			if !response.isError() {
				response.messageVal, response.val = response.val, nil
			}
			s.auditAnnotations = append(s.auditAnnotations, response)
		}
	}
}

// evaluateMessageExpressions returns one entry per validation, nil where the
// validation has no messageExpression. The returned slice is also published as
// its own section, so the cost and any failure of a messageExpression is
// visible next to the validation it belongs to, rather than folded into it.
func (s *evalSections) evaluateMessageExpressions(compiler *policyCompiler, inputs *evalInputs, celInfo *CelInformation) evalResponses {
	messages := make(evalResponses, len(celInfo.validations))
	for i, validation := range celInfo.validations {
		if validation.messageExpression == "" {
			continue
		}
		if s.messageScope == nil {
			s.messageScope = compiler.newScope(inputs, messageBindings)
		}
		messages[i] = s.messageScope.evalExpression("", &messageExpression{expression: validation.messageExpression}, declsWithoutAuthorizer)
	}
	if s.messageScope != nil {
		s.messageExpressions = messages
	}
	return messages
}

// resolveMessage is the failure message a cluster would report for a validation
// that did not pass. A messageExpression wins, but only if it produced a single
// line of no more than MaxEvaluatedMessageExpressionSizeBytes; otherwise the
// literal message is used, and failing that the expression itself.
func resolveMessage(validation CelValidationInfo, evaluated *evalResponse) string {
	message := ""
	if value, ok := evaluated.stringValue(); ok {
		value = strings.TrimSpace(value)
		if len(value) <= celconfig.MaxEvaluatedMessageExpressionSizeBytes && !strings.ContainsAny(value, "\n") {
			message = value
		}
	}
	if message == "" {
		message = strings.TrimSpace(validation.message)
	}
	if message == "" {
		message = fmt.Sprintf("failed expression: %v", strings.TrimSpace(validation.expression))
	}
	return message
}
