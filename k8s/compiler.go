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
	"context"
	"errors"
	"fmt"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter"
	"k8s.io/apimachinery/pkg/util/version"
	celplugin "k8s.io/apiserver/pkg/admission/plugin/cel"
	apiservercel "k8s.io/apiserver/pkg/cel"
	"k8s.io/apiserver/pkg/cel/environment"
	"k8s.io/apiserver/pkg/cel/lazy"
)

// playgroundEnvVersion is the Kubernetes compatibility version the playground
// compiles against. environment.MustBaseEnvSet gates each CEL library on the
// version it shipped in, so this is what decides which functions a policy may
// use. Bump it in lockstep with the k8s.io/apiserver dependency.
var playgroundEnvVersion = version.MajorMinor(1, 36)

// variablesTypeName must match the type name apiserver's CompositedCompiler
// registers for the `variables` map (see composition.go upstream); the lazy map
// bound at evaluation time reports it as its own runtime type.
const variablesTypeName = "kubernetes.variables"

// The expression accessors below are local copies of the ones apiserver defines
// in pkg/admission/plugin/policy/validating. That package cannot be imported:
// it pulls in policy/generic -> webhook/generic -> util/webhook, which drags in
// egressselector (grpc, konnectivity) and component-base/tracing (OTLP). Only
// the ReturnTypes matter to the compiler, and they are reproduced verbatim.

type matchConditionExpression struct{ expression string }

func (e *matchConditionExpression) GetExpression() string { return e.expression }

func (e *matchConditionExpression) ReturnTypes() []*celgo.Type {
	return []*celgo.Type{celgo.BoolType}
}

type validationExpression struct{ expression string }

func (e *validationExpression) GetExpression() string { return e.expression }

func (e *validationExpression) ReturnTypes() []*celgo.Type {
	return []*celgo.Type{celgo.BoolType}
}

type messageExpression struct{ expression string }

func (e *messageExpression) GetExpression() string { return e.expression }

func (e *messageExpression) ReturnTypes() []*celgo.Type {
	return []*celgo.Type{celgo.StringType}
}

type auditAnnotationExpression struct{ expression string }

func (e *auditAnnotationExpression) GetExpression() string { return e.expression }

func (e *auditAnnotationExpression) ReturnTypes() []*celgo.Type {
	return []*celgo.Type{celgo.StringType, celgo.NullType}
}

type variableExpression struct {
	name       string
	expression string
}

func (e *variableExpression) GetExpression() string { return e.expression }

func (e *variableExpression) GetName() string { return e.name }

func (e *variableExpression) ReturnTypes() []*celgo.Type {
	return []*celgo.Type{celgo.AnyType, celgo.DynType}
}

// evalActivation mirrors apiserver's own (unexported) evaluationActivation. The
// playground has to build its own because it evaluates each expression itself
// -- see celEvaluator.evalExpression for why -- but the variable names and the
// "declared but unbound" behaviour of authorizer are kept identical.
type evalActivation struct {
	object, oldObject, params, request, namespace, authorizer, requestResourceAuthorizer, variables any
}

func (a *evalActivation) ResolveName(name string) (any, bool) {
	switch name {
	case celplugin.ObjectVarName:
		return a.object, true
	case celplugin.OldObjectVarName:
		return a.oldObject, true
	case celplugin.ParamsVarName:
		return a.params, true
	case celplugin.RequestVarName:
		return a.request, true
	case celplugin.NamespaceVarName:
		return a.namespace, true
	case celplugin.AuthorizerVarName:
		return a.authorizer, a.authorizer != nil
	case celplugin.RequestResourceAuthorizerVarName:
		return a.requestResourceAuthorizer, a.requestResourceAuthorizer != nil
	case celplugin.VariableVarName:
		return a.variables, true
	default:
		return nil, false
	}
}

func (a *evalActivation) Parent() interpreter.Activation { return nil }

// celEvaluator compiles and evaluates one scope's worth of expressions with
// apiserver's own compiler.
//
// It deliberately does NOT go through celplugin.ConditionEvaluator.ForInput.
// ForInput evaluates a whole batch and only reports one aggregate
// `remainingBudget`; EvaluationResult carries no per-expression cost. The
// playground's result panel shows a cost per validation, per matchCondition and
// per variable, so the evaluation loop that upstream keeps in its unexported
// evaluationActivation.Evaluate is reproduced here (about 20 lines) on top of
// the exported CompilationResult.Program. Everything that decides *semantics* --
// the environment, the type check, the cost estimator, the program options --
// still comes from upstream.
type celEvaluator struct {
	compiler   *celplugin.CompositedCompiler
	decls      celplugin.OptionalVariableDeclarations
	ctx        context.Context
	activation *evalActivation

	// variableNames preserves spec.variables order for the result panel.
	variableNames []string
	// compiledVariables and variableResults are keyed by variable name.
	// variableResults only gains an entry when a variable is actually
	// dereferenced, which is how the UI distinguishes an evaluated variable
	// from one no expression ever read.
	compiledVariables map[string]celplugin.CompilationResult
	variableResults   evalResults
}

func newCelEvaluator(inputs *evalInputs, variables []CelVariableInfo) (*celEvaluator, error) {
	compiler, err := celplugin.NewCompositedCompiler(environment.MustBaseEnvSet(playgroundEnvVersion))
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL compiler: %w", err)
	}
	e := &celEvaluator{
		compiler: compiler,
		// HasAuthorizer declares `authorizer` and `authorizer.requestResource`
		// with apiserver's own library.Authz types, so the playground now runs
		// the real authorization CEL library rather than a hand-rolled
		// look-alike. HasParams stays false until the playground grows a params
		// input tab.
		decls:             celplugin.OptionalVariableDeclarations{HasAuthorizer: true},
		ctx:               context.Background(),
		compiledVariables: map[string]celplugin.CompilationResult{},
		variableResults:   evalResults{},
		activation:        &evalActivation{},
	}
	if inputs.object != nil {
		e.activation.object = inputs.object
	}
	if inputs.oldObject != nil {
		e.activation.oldObject = inputs.oldObject
	}
	if inputs.request != nil {
		e.activation.request = inputs.request
	}
	if inputs.namespaceObject != nil {
		e.activation.namespace = inputs.namespaceObject
	}
	e.activation.authorizer = inputs.authorizer
	e.activation.requestResourceAuthorizer = inputs.requestResourceAuthorizer
	e.compileVariables(variables)
	return e, nil
}

// compileVariables compiles spec.variables in order -- order matters, a variable
// may reference the ones declared before it -- and binds `variables` to a lazy
// map whose callbacks evaluate on first dereference and record the cost of that
// evaluation. That is the same laziness and the same memoisation apiserver gets
// from its composition context, with the per-variable cost kept.
func (e *celEvaluator) compileVariables(variables []CelVariableInfo) {
	lazyMap := lazy.NewMapValue(apiservercel.NewObjectType(variablesTypeName, map[string]*apiservercel.DeclField{}))
	for _, variable := range variables {
		accessor := &variableExpression{name: variable.name, expression: variable.expression}
		e.compiledVariables[variable.name] = e.compiler.CompileAndStoreVariable(accessor, e.decls, environment.StoredExpressions)
		e.variableNames = append(e.variableNames, variable.name)
		lazyMap.Append(variable.name, e.variableCallback(variable.name))
	}
	e.activation.variables = lazyMap
}

func (e *celEvaluator) variableCallback(name string) lazy.GetFieldFunc {
	return func(_ *lazy.MapValue) ref.Val {
		result := e.compiledVariables[name]
		var response *evalResponse
		if result.Error != nil {
			response = newEvalResponseCompilationErr(name, result.Error)
		} else if val, details, err := result.Program.ContextEval(e.ctx, e.activation); err != nil {
			response = newEvalResponseErr("evaluating", name, err)
		} else {
			response = newEvalResponse(name, val, details, "", nil)
		}
		e.variableResults[name] = response
		return response.val
	}
}

// evalExpression compiles and evaluates a single expression. A compilation
// failure is reported as a result rather than returned as a Go error: a
// mistyped expression is the answer the playground exists to give.
func (e *celEvaluator) evalExpression(name string, accessor celplugin.ExpressionAccessor) *evalResponse {
	result := e.compiler.CompileCELExpression(accessor, e.decls, environment.StoredExpressions)
	if result.Error != nil {
		return newEvalResponseCompilationErr(name, result.Error)
	}
	val, details, err := result.Program.ContextEval(e.ctx, e.activation)
	if err != nil {
		return newEvalResponseErr("evaluating", accessor.GetExpression(), err)
	}
	return newEvalResponse(name, val, details, "", nil)
}

// newEvalResponseCompilationErr reports a type-check or compilation failure --
// the class of mistake the playground previously could not see at all, because
// env.Parse only ever caught syntax errors. There is no cost: nothing ran.
//
// The failure is wrapped as an evalResponseError so that an expression which
// dereferences a variable that failed to compile reports the variable's
// compilation error as its cause, the same way a runtime failure does.
func newEvalResponseCompilationErr(name string, err error) *evalResponse {
	detail := err.Error()
	var celErr *apiservercel.Error
	if errors.As(err, &celErr) {
		detail = celErr.Detail
	}
	compilationErr := errors.New(detail)
	if name != "" {
		compilationErr = fmt.Errorf("%s: %s", name, detail)
	}
	return &evalResponse{name: name, val: types.WrapErr(&evalResponseError{compilationErr, compilationErr})}
}
