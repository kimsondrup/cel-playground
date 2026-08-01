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
	celconfig "k8s.io/apiserver/pkg/apis/cel"
)

type evalResponseError struct {
	error
	cause error
}

// newEvalResponseErr reports an expression that ran and failed. It carries the
// cost of the attempt: cel-go accounts for the work done before the failure and
// the apiserver charges that against the request's budget, so an erroring
// expression is not free.
func newEvalResponseErr(name, operation, expression string, err error, details *cel.EvalDetails) *evalResponse {
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
			name: name,
			cost: getCost(details),
			val:  types.WrapErr(&evalResponseError{fmt.Errorf("unexpected error %s expression '%s', caused by nested exception: '%s'", operation, expression, evalErr.cause), evalErr.cause}),
		}
	}
	return &evalResponse{
		name: name,
		cost: getCost(details),
		val:  types.WrapErr(&evalResponseError{fmt.Errorf("unexpected error %s expression %s: %s", operation, expression, underlying), underlying}),
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

// stringValue returns the expression's result when it is a string.
func (r *evalResponse) stringValue() (string, bool) {
	if r == nil || r.isError() || r.val == nil {
		return "", false
	}
	value, ok := r.val.Value().(string)
	return value, ok
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

// EvalResponse is the whole result panel. Each variable list belongs to one of
// the batches the apiserver evaluates a policy in; a variable read from two
// batches appears in two lists because a cluster evaluates, and charges for, it
// twice.
type EvalResponse struct {
	// ExceededBudgets names the cost budgets this evaluation ran past, and is
	// absent when it ran past none. It comes first because it is the one thing
	// in the panel that says the request would have been rejected outright.
	ExceededBudgets            []*EvalResult   `json:"exceededBudgets,omitempty"`
	MatchConditions            []*EvalResult   `json:"matchConditions,omitempty"`
	ValidationVariables        []*EvalVariable `json:"validationVariables,omitempty"`
	Validations                []*EvalResult   `json:"validations,omitempty"`
	MessageExpressionVariables []*EvalVariable `json:"messageExpressionVariables,omitempty"`
	MessageExpressions         []*EvalResult   `json:"messageExpressions,omitempty"`
	AuditAnnotationVariables   []*EvalVariable `json:"auditAnnotationVariables,omitempty"`
	AuditAnnotations           []*EvalResult   `json:"auditAnnotations,omitempty"`
	WebhookMatchConditions     [][]*EvalResult `json:"webhookMatchConditions,omitempty"`
	Cost                       *uint64         `json:"cost,omitempty"`
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

func generateEvalVariables(scope *evalScope) []*EvalVariable {
	if scope == nil {
		return nil
	}
	variables := []*EvalVariable{}
	for _, name := range scope.variableNames {
		if result, ok := scope.variableResults[name]; ok && result != nil {
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
		// A section may be sparse -- messageExpressions has a slot per
		// validation and most validations declare none. An empty row is
		// indistinguishable from one that evaluated to nothing, so the slot is
		// dropped and the rows that remain name the validation they belong to.
		if eval == nil {
			continue
		}
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

func calculateVariablesCost(scope *evalScope) uint64 {
	if scope == nil {
		return 0
	}
	var cost uint64
	for _, result := range scope.variableResults {
		if result != nil && result.cost != nil {
			cost += *result.cost
		}
	}
	return cost
}

func calculateEvalResponsesCost(evals evalResponses) uint64 {
	var cost uint64
	for _, eval := range evals {
		if eval != nil && eval.cost != nil {
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

// evalSections is one evaluation's worth of results, one entry per batch the
// apiserver would evaluate. A nil scope is a batch the mode does not have.
type evalSections struct {
	matchConditions evalResponses

	validationScope *evalScope
	validations     evalResponses

	messageScope       *evalScope
	messageExpressions evalResponses

	auditAnnotationScope *evalScope
	auditAnnotations     evalResponses

	webhookMatchConditions []evalResponses
}

// chainCosts is what each of the apiserver's cost budgets is checked against.
// There is no single pot: matchConditions have their own, the validations and
// the messageExpressions share one, and the audit annotations start again from
// a full one.
func (s *evalSections) chainCosts() (matchConditions, validations, auditAnnotations uint64) {
	matchConditions = calculateEvalResponsesCost(s.matchConditions) +
		calculateEvalResponsesArrayCost(s.webhookMatchConditions)
	validations = calculateVariablesCost(s.validationScope) +
		calculateEvalResponsesCost(s.validations) +
		calculateVariablesCost(s.messageScope) +
		calculateEvalResponsesCost(s.messageExpressions)
	auditAnnotations = calculateVariablesCost(s.auditAnnotationScope) +
		calculateEvalResponsesCost(s.auditAnnotations)
	return matchConditions, validations, auditAnnotations
}

// exceededBudgets reports the chains that ran past the budget the apiserver
// checks them against. A cluster abandons the rest of a chain at that point and
// fails the request; the playground keeps evaluating, so that the expression
// that overran is still visible, and says so here instead.
func (s *evalSections) exceededBudgets() []*EvalResult {
	_, validations, auditAnnotations := s.chainCosts()
	var exceeded []*EvalResult
	report := func(name string, cost uint64, budget uint64) {
		if cost <= budget {
			return
		}
		message := fmt.Sprintf("%d, over the %d the apiserver allows; a cluster would abandon the rest and fail the request", cost, budget)
		exceeded = append(exceeded, &EvalResult{
			Name:    &name,
			Cost:    &cost,
			IsError: true,
			Error:   &message,
		})
	}
	// Every set of matchConditions is matched on its own, so each webhook in a
	// configuration gets a whole budget rather than a share of one.
	report("matchConditions", calculateEvalResponsesCost(s.matchConditions), celconfig.RuntimeCELCostBudgetMatchConditions)
	for i, webhook := range s.webhookMatchConditions {
		report(fmt.Sprintf("webhooks[%d].matchConditions", i), calculateEvalResponsesCost(webhook), celconfig.RuntimeCELCostBudgetMatchConditions)
	}
	report("validations and messageExpressions", validations, celconfig.RuntimeCELCostBudget)
	report("auditAnnotations", auditAnnotations, celconfig.RuntimeCELCostBudget)
	return exceeded
}

// response totals the cost the way the apiserver charges it: every expression
// that ran, plus every variable evaluation each batch triggered. The total is
// not itself checked against anything -- see exceededBudgets for the budgets
// that are.
func (s *evalSections) response() *EvalResponse {
	matchConditions, validations, auditAnnotations := s.chainCosts()
	cost := matchConditions + validations + auditAnnotations

	return &EvalResponse{
		ExceededBudgets:            s.exceededBudgets(),
		MatchConditions:            generateEvalResults(s.matchConditions),
		ValidationVariables:        generateEvalVariables(s.validationScope),
		Validations:                generateEvalResults(s.validations),
		MessageExpressionVariables: generateEvalVariables(s.messageScope),
		MessageExpressions:         generateEvalResults(s.messageExpressions),
		AuditAnnotationVariables:   generateEvalVariables(s.auditAnnotationScope),
		AuditAnnotations:           generateEvalResults(s.auditAnnotations),
		WebhookMatchConditions:     generateEvalArrayResults(s.webhookMatchConditions),
		Cost:                       &cost,
	}
}
