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
	celplugin "k8s.io/apiserver/pkg/admission/plugin/cel"
	apiservercel "k8s.io/apiserver/pkg/cel"
	"k8s.io/apiserver/pkg/cel/environment"
	"k8s.io/apiserver/pkg/cel/lazy"
)

// baseEnvSet is the CEL environment an apiserver compiles admission expressions
// in. environment.DefaultCompatibilityVersion reports the minimum version the
// running apiserver stays compatible with, which is one minor behind the binary
// -- so a CEL library that shipped in the current minor is not usable until the
// next release. Both upstream compile paths the playground mirrors
// (plugin/policy/validating and plugin/webhook/generic) pass exactly this.
//
// Expressions are compiled as environment.NewExpressions, which is the gate an
// author hits: it withholds anything behind a disabled feature gate, where
// StoredExpressions offers it so that an expression already stored on a cluster
// keeps working. Compiling as StoredExpressions would let the playground accept
// what the version in the footer says it will not.
func baseEnvSet() *environment.EnvSet {
	return environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion())
}

// PlaygroundEnvVersion reports the Kubernetes version whose CEL environment the
// playground compiles against, for display in the UI.
func PlaygroundEnvVersion() string {
	return environment.DefaultCompatibilityVersion().String()
}

// variablesTypeName must match the type name apiserver's CompositedCompiler
// registers for the `variables` map (see composition.go upstream); the lazy map
// bound at evaluation time reports it as its own runtime type.
const variablesTypeName = "kubernetes.variables"

// The expression accessors below are local copies of the ones apiserver defines
// in pkg/admission/plugin/policy/validating. That package cannot be imported:
// it pulls in policy/generic -> webhook/generic -> util/webhook, which drags in
// egressselector (grpc, konnectivity) and component-base/tracing (OTLP). Only
// the ReturnTypes matter to the compiler, and they are reproduced verbatim.
// k8s/oracle is a separate module and does import it, so the copies are fenced
// by a differential test against the real thing.

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

// declsFor returns the declarations everything except a messageExpression is
// compiled with: matchConditions, validations and audit annotations in a
// policy, and a webhook's matchConditions.
//
// `params` is declared exactly when the policy declares spec.paramKind, which
// is the rule the apiserver applies. The playground has no params tab, so it is
// declared and left null -- a state a cluster reaches too, when the binding's
// paramRef selects nothing.
func declsFor(hasParams bool) celplugin.OptionalVariableDeclarations {
	return celplugin.OptionalVariableDeclarations{HasParams: hasParams, HasAuthorizer: true}
}

// declsForMessage compiles a messageExpression. The apiserver deliberately does
// not declare `authorizer` there -- a message is rendered after the decision is
// made, so it may not ask new authorization questions, and naming it is a
// compilation error rather than a runtime one.
func declsForMessage(hasParams bool) celplugin.OptionalVariableDeclarations {
	return celplugin.OptionalVariableDeclarations{HasParams: hasParams, HasAuthorizer: false}
}

// evalActivation mirrors apiserver's own (unexported) evaluationActivation. The
// playground has to build its own because it evaluates each expression itself
// -- see evalScope.evalExpression for why -- but the variable names and the
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

// scopeBindings selects which of the optional CEL variables a scope binds.
//
// Declared-but-unbound is a real state: `authorizer` type-checks in an audit
// annotation, because the annotation is compiled with the same declarations as
// the validations, but it resolves to nothing at evaluation time, so an audit
// annotation that calls it fails at runtime on a cluster.
type scopeBindings struct {
	authorizer      bool
	namespaceObject bool
}

// The four batches an apiserver evaluates a ValidatingAdmissionPolicy in, and
// the bindings each one is given (plugin/policy/validating/validator.go and
// plugin/webhook/matchconditions/matcher.go).
var (
	matchConditionBindings  = scopeBindings{authorizer: true, namespaceObject: false}
	validationBindings      = scopeBindings{authorizer: true, namespaceObject: true}
	messageBindings         = scopeBindings{authorizer: false, namespaceObject: true}
	auditAnnotationBindings = scopeBindings{authorizer: false, namespaceObject: true}
)

func newEvalActivation(inputs *evalInputs, bindings scopeBindings) *evalActivation {
	activation := &evalActivation{
		object:    inputs.object,
		oldObject: inputs.oldObject,
		request:   inputs.request,
	}
	if bindings.namespaceObject {
		activation.namespace = inputs.namespaceObject
	}
	if bindings.authorizer {
		activation.authorizer = inputs.authorizer
		activation.requestResourceAuthorizer = inputs.requestResourceAuthorizer
	}
	return activation
}

// policyCompiler holds the compiled form of one ValidatingAdmissionPolicy.
//
// A CompositedCompiler must not outlive the policy it compiled: storing a
// variable mutates the shared `variables` DeclType in place and there is no
// exported reset, so a reused compiler lets a policy that declares no variables
// type-check `variables.foo` left over from an earlier one. Within a single
// policy the compiler is shared across scopes, which is both what the apiserver
// does and, since compiling the base environment dominates an evaluation, most
// of the playground's per-run cost.
type policyCompiler struct {
	compiler          *celplugin.CompositedCompiler
	variableNames     []string
	compiledVariables map[string]celplugin.CompilationResult
}

// newPolicyCompiler compiles spec.variables in order -- order matters, a
// variable may reference the ones declared before it.
func newPolicyCompiler(celInfo *CelInformation) (*policyCompiler, error) {
	compiler, err := celplugin.NewCompositedCompiler(baseEnvSet())
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL compiler: %w", err)
	}
	p := &policyCompiler{
		compiler:          compiler,
		compiledVariables: make(map[string]celplugin.CompilationResult, len(celInfo.variables)),
	}
	for _, variable := range celInfo.variables {
		accessor := &variableExpression{name: variable.name, expression: variable.expression}
		p.compiledVariables[variable.name] = compiler.CompileAndStoreVariable(accessor, declsFor(celInfo.hasParams), environment.NewExpressions)
		p.variableNames = append(p.variableNames, variable.name)
	}
	return p, nil
}

// evalScope evaluates one batch of expressions against one binding of
// `variables`.
//
// The apiserver evaluates a policy in four batches -- matchConditions,
// validations, auditAnnotations and messageExpressions -- and each batch calls
// ConditionEvaluator.ForInput, which builds a fresh lazy `variables` map. A
// variable is therefore memoised, and charged, once per batch. evalScope is
// that batch: one scope per ForInput the apiserver would make.
type evalScope struct {
	compiler celplugin.Compiler
	ctx      context.Context

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

// newScope binds a fresh lazy `variables` map over the policy's compiled
// variables. Each variable is evaluated on first dereference within the scope
// and its cost recorded, which is the laziness, memoisation and cost accounting
// apiserver gets from its composition context.
func (p *policyCompiler) newScope(inputs *evalInputs, bindings scopeBindings) *evalScope {
	s := &evalScope{
		compiler:          p.compiler,
		ctx:               context.Background(),
		activation:        newEvalActivation(inputs, bindings),
		variableNames:     p.variableNames,
		compiledVariables: p.compiledVariables,
		variableResults:   evalResults{},
	}
	lazyMap := lazy.NewMapValue(apiservercel.NewObjectType(variablesTypeName, map[string]*apiservercel.DeclField{}))
	for _, name := range p.variableNames {
		lazyMap.Append(name, s.variableCallback(name))
	}
	s.activation.variables = lazyMap
	return s
}

// newMatchConditionScope compiles matchConditions, for a policy as well as for
// a webhook, without declaring `variables`.
//
// A webhook has no spec.variables at all: the apiserver compiles its
// matchConditions with a plain ConditionCompiler rather than a composited one,
// so naming `variables` there does not compile.
//
// A policy does have them, and the apiserver's *runtime* compiler does declare
// them for matchConditions -- but its registry validation does not, so
// `kubectl apply` of such a policy fails with "undeclared reference to
// 'variables'" and no cluster ever stores one. Of the apiserver's two gates the
// playground shows the one an author hits first, and reports the same
// compilation error the apiserver would.
func newMatchConditionScope(inputs *evalInputs) *evalScope {
	return &evalScope{
		compiler:        celplugin.NewCompiler(baseEnvSet()),
		ctx:             context.Background(),
		activation:      newEvalActivation(inputs, matchConditionBindings),
		variableResults: evalResults{},
	}
}

func (s *evalScope) variableCallback(name string) lazy.GetFieldFunc {
	return func(_ *lazy.MapValue) ref.Val {
		result := s.compiledVariables[name]
		var response *evalResponse
		if result.Error != nil {
			response = newEvalResponseCompilationErr(name, result.Error)
		} else if val, details, err := result.Program.ContextEval(s.ctx, s.activation); err != nil {
			response = newEvalResponseErr(name, "evaluating", name, err, details)
		} else {
			response = newEvalResponse(name, val, details, "", nil)
		}
		s.variableResults[name] = response
		return response.val
	}
}

// evalExpression compiles and evaluates a single expression.
//
// It deliberately does not go through celplugin.ConditionEvaluator.ForInput.
// ForInput evaluates a whole batch and only reports one aggregate
// remainingBudget; EvaluationResult carries no per-expression cost. The
// playground's result panel shows a cost per validation, per matchCondition and
// per variable, so the evaluation loop that upstream keeps in its unexported
// evaluationActivation.Evaluate is reproduced here on top of the exported
// CompilationResult.Program. Everything that decides *semantics* -- the
// environment, the type check, the cost estimator, the program options -- still
// comes from upstream.
//
// A compilation failure is reported as a result rather than returned as a Go
// error: a mistyped expression is the answer the playground exists to give.
func (s *evalScope) evalExpression(name string, accessor celplugin.ExpressionAccessor, decls celplugin.OptionalVariableDeclarations) *evalResponse {
	result := s.compiler.CompileCELExpression(accessor, decls, environment.NewExpressions)
	if result.Error != nil {
		return newEvalResponseCompilationErr(name, result.Error)
	}
	val, details, err := result.Program.ContextEval(s.ctx, s.activation)
	if err != nil {
		return newEvalResponseErr(name, "evaluating", accessor.GetExpression(), err, details)
	}
	return newEvalResponse(name, val, details, "", nil)
}

// newEvalResponseCompilationErr reports a type-check or compilation failure.
// There is no cost: nothing ran.
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
