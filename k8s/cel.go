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
	"github.com/google/cel-go/ext"
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
}

var celProgramOptions = []cel.ProgramOption{
	cel.EvalOptions(cel.OptOptimize, cel.OptTrackCost),
}
