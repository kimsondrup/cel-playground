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
	"errors"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/undistro/cel-playground/utils"
)

type evalResponseError struct {
	error
	cause error
}

func newEvalResponseErr(operation, expression string, err error) *evalResponse {
	underlying := err
	if celErr, ok := err.(*types.Err); ok {
		underlying = celErr.Unwrap()
	}
	// An expression that dereferenced a variable which itself failed reports the
	// variable's failure as the cause, so the panel points at the real culprit.
	// cel-go does not always hand the error back as a *types.Err, so unwrap the
	// chain rather than type-switching on the top-level value.
	var evalErr *evalResponseError
	if errors.As(underlying, &evalErr) {
		return &evalResponse{
			val: types.WrapErr(&evalResponseError{fmt.Errorf("unexpected error %s expression '%s', caused by nested exception: '%s'", operation, expression, evalErr.cause), evalErr.cause}),
		}
	}
	return &evalResponse{
		val: types.WrapErr(&evalResponseError{fmt.Errorf("unexpected error %s expression %s: %s", operation, expression, underlying), underlying}),
	}
}

type evalResponse struct {
	name string
	val  ref.Val
	// cost is the CEL runtime cost this response accounts for. It is nil when
	// nothing ran -- a compilation failure costs nothing.
	cost       *uint64
	messageVal ref.Val
	message    string
}

type evalResponses []*evalResponse

func newEvalResponse(name string, exprEval ref.Val, details *cel.EvalDetails, message string, messageVal ref.Val) *evalResponse {
	return &evalResponse{
		name:       name,
		val:        exprEval,
		cost:       getCost(details),
		messageVal: messageVal,
		message:    message,
	}
}

// isError reports whether the expression produced an error rather than a value.
func (r *evalResponse) isError() bool {
	if r == nil || r.val == nil {
		return false
	}
	_, ok := r.val.Value().(error)
	return ok
}

// addCost folds a second expression's cost into this response. A validation
// whose messageExpression also ran is charged for both, the way the apiserver
// charges both against the request's cost budget.
func (r *evalResponse) addCost(cost *uint64) {
	if cost == nil {
		return
	}
	if r.cost == nil {
		total := *cost
		r.cost = &total
		return
	}
	total := *r.cost + *cost
	r.cost = &total
}

// evalResults holds the lazily evaluated variables of one scope, keyed by name.
// A variable only gains an entry once some expression dereferences it.
type evalResults map[string]*evalResponse

type EvalVariable struct {
	Name    string  `json:"name"`
	Value   any     `json:"value,omitempty"`
	Cost    *uint64 `json:"cost,omitempty"`
	IsError bool    `json:"isError,omitempty"`
	Error   *string `json:"error,omitempty"`
}

type EvalResult struct {
	Name    *string `json:"name,omitempty"`
	Result  any     `json:"result,omitempty"`
	Cost    *uint64 `json:"cost,omitempty"`
	Error   *string `json:"error,omitempty"`
	IsError bool    `json:"isError,omitempty"`
	Message any     `json:"message,omitempty"`
}

type EvalResponse struct {
	MatchConditionsVariables []*EvalVariable `json:"matchConditionVariables,omitempty"`
	MatchConditions          []*EvalResult   `json:"matchConditions,omitempty"`
	ValidationVariables      []*EvalVariable `json:"validationVariables,omitempty"`
	Validations              []*EvalResult   `json:"validations,omitempty"`
	AuditAnnotations         []*EvalResult   `json:"auditAnnotations,omitempty"`
	WebhookMatchConditions   [][]*EvalResult `json:"webhookMatchConditions,omitempty"`
	Cost                     *uint64         `json:"cost,omitempty"`
}

func getResults(val ref.Val) (any, *string) {
	if val == nil {
		return nil, nil
	}
	value := val.Value()
	if err, ok := value.(error); ok {
		errResponse := err.Error()
		return nil, &errResponse
	}

	if value, err := utils.ConvertValToNative(val); err != nil {
		errResponse := err.Error()
		return nil, &errResponse
	} else {
		return value, nil
	}
}

func getCost(details *cel.EvalDetails) *uint64 {
	if details == nil {
		return nil
	}
	return details.ActualCost()
}

func generateEvalVariables(names []string, results evalResults) []*EvalVariable {
	variables := []*EvalVariable{}
	for _, name := range names {
		if result, ok := results[name]; ok && result != nil {
			value, err := getResults(result.val)
			variables = append(variables, &EvalVariable{
				Name:    name,
				Value:   value,
				Cost:    result.cost,
				Error:   err,
				IsError: err != nil,
			})
		}
	}
	return variables
}

func generateEvalResults(responses evalResponses) []*EvalResult {
	evals := []*EvalResult{}
	for _, eval := range responses {
		value, err := getResults(eval.val)
		var message any
		if eval.messageVal != nil {
			message, _ = getResults(eval.messageVal)
		} else if eval.message != "" {
			message = eval.message
		}
		var name *string
		if eval.name != "" {
			name = &eval.name
		}
		evals = append(evals, &EvalResult{
			Name:    name,
			Result:  value,
			Cost:    eval.cost,
			Error:   err,
			IsError: err != nil,
			Message: message,
		})
	}
	return evals
}

func generateEvalArrayResults(responses []evalResponses) [][]*EvalResult {
	evalsArray := [][]*EvalResult{}
	for _, response := range responses {
		evals := generateEvalResults(response)
		evalsArray = append(evalsArray, evals)
	}
	return evalsArray
}

func calculateVariablesCost(results evalResults) uint64 {
	var cost uint64
	for _, result := range results {
		if result != nil && result.cost != nil {
			cost += *result.cost
		}
	}
	return cost
}

func calculateEvalResponsesCost(evals evalResponses) uint64 {
	var cost uint64
	for _, eval := range evals {
		if eval.cost != nil {
			cost += *eval.cost
		}
	}
	return cost
}

func calculateEvalResponsesArrayCost(evalsArray []evalResponses) uint64 {
	var cost uint64
	for _, evals := range evalsArray {
		cost += calculateEvalResponsesCost(evals)
	}
	return cost
}

func generateEvalResponse(matchConditionsVariableNames []string, matchConditionsVariables evalResults, matchConditionsEvals evalResponses,
	validationVariableNames []string, validationVariables evalResults, validationEvals evalResponses,
	auditAnnotationEvals evalResponses, webhookMatchConditionsEvals []evalResponses) *EvalResponse {

	cost := calculateVariablesCost(matchConditionsVariables)
	cost += calculateEvalResponsesCost(matchConditionsEvals)
	cost += calculateVariablesCost(validationVariables)
	cost += calculateEvalResponsesCost(validationEvals)
	cost += calculateEvalResponsesCost(auditAnnotationEvals)
	cost += calculateEvalResponsesArrayCost(webhookMatchConditionsEvals)

	return &EvalResponse{
		MatchConditionsVariables: generateEvalVariables(matchConditionsVariableNames, matchConditionsVariables),
		MatchConditions:          generateEvalResults(matchConditionsEvals),
		ValidationVariables:      generateEvalVariables(validationVariableNames, validationVariables),
		Validations:              generateEvalResults(validationEvals),
		AuditAnnotations:         generateEvalResults(auditAnnotationEvals),
		WebhookMatchConditions:   generateEvalArrayResults(webhookMatchConditionsEvals),
		Cost:                     &cost,
	}
}
