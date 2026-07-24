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
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
	"github.com/google/cel-go/ext"
	"github.com/google/cel-go/interpreter"
	k8s "k8s.io/apiserver/pkg/cel/library"
)

// celEnvOptions mirrors the CEL library set that apiserver's base environment
// (k8s.io/apiserver/pkg/cel/environment.MustBaseEnvSet) registers, so a
// matchCondition, validation or variable evaluated here sees the same functions
// a real cluster exposes. The libraries below are listed with the Kubernetes
// version each became available, matching apiserver's base.go.
//
// library.Authz() / library.AuthzSelectors() are deliberately NOT enabled: the
// authorizer is hand-rolled (see authorizer.go) and bound as a CEL variable
// instead. That is the one library a real cluster has and this env does not.
var celEnvOptions = []cel.EnvOption{
	cel.EagerlyValidateDeclarations(true),
	cel.DefaultUTCTimeZone(true),
	cel.CrossTypeNumericComparisons(true),
	cel.OptionalTypes(),
	ext.Strings(ext.StringsVersion(2)), // 1.29
	ext.Sets(),                         // 1.29
	ext.TwoVarComprehensions(),         // 1.32
	ext.Lists(ext.ListsVersion(3)),     // 1.34
	k8s.URLs(),
	k8s.Regex(),
	k8s.Lists(),
	k8s.Quantity(),                      // 1.28
	k8s.IP(),                            // 1.30
	k8s.CIDR(),                          // 1.30
	k8s.Format(),                        // 1.31
	k8s.SemverLib(k8s.SemverVersion(1)), // 1.33

	// Cost accounting, also from apiserver's base.go, so a displayed cost is
	// close to what a real cluster charges: the k8s CostEstimator in the program
	// options below prices the extended-library functions (ip, cidr, url,
	// semver, ...) and, most visibly, an authorizer check() at its real 350000
	// instead of cel-go's defaults.
	//
	// Close, not exact. Expressions using variables.*, string concatenation or
	// `in` over a typed list still undercharge slightly, because this env parses
	// expressions (env.Parse) where the apiserver compiles and type-checks them,
	// so those overloads fall back to cel-go's default cost. Closing that gap
	// means switching Parse to Compile, a separate change.
	//
	// CostEstimatorOptions is currently a no-op -- nothing here runs the static
	// estimator, only Parse and eval -- but it is kept so this stays a faithful
	// mirror of base.go, and it becomes load-bearing the moment anyone switches
	// to Compile. Do not delete it as dead code.
	cel.CostEstimatorOptions(checker.PresenceTestHasCost(false)),
}

var celProgramOptions = []cel.ProgramOption{
	cel.EvalOptions(cel.OptOptimize, cel.OptTrackCost),
	cel.CostTrackerOptions(interpreter.PresenceTestHasCost(false)),
	cel.CostTracking(&k8s.CostEstimator{}),
}
