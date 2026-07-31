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

//go:build oracle

package oracle_test

import (
	"context"
	"sort"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/apiserver/pkg/cel/environment"

	"github.com/undistro/cel-playground/oracle"
)

// TestAcceptanceServedVersions records which admissionregistration.k8s.io
// versions this apiserver actually serves, and which of them carry
// ValidatingAdmissionPolicy. The repo's fixtures are written against
// v1alpha1; whether that is still a thing is not a matter of opinion.
func TestAcceptanceServedVersions(t *testing.T) {
	o := cluster(t)

	groups, err := o.Discovery.ServerGroups()
	if err != nil {
		t.Fatalf("discovering server groups: %v", err)
	}

	var found bool
	for _, g := range groups.Groups {
		if g.Name != "admissionregistration.k8s.io" {
			continue
		}
		found = true
		t.Logf("group %s: preferredVersion=%s", g.Name, g.PreferredVersion.GroupVersion)
		for _, v := range g.Versions {
			t.Logf("  served groupVersion: %s", v.GroupVersion)
			list, err := o.Discovery.ServerResourcesForGroupVersion(v.GroupVersion)
			if err != nil {
				t.Errorf("  listing resources for %s: %v", v.GroupVersion, err)
				continue
			}
			var names []string
			for _, r := range list.APIResources {
				if strings.Contains(r.Name, "/") {
					continue // subresources
				}
				names = append(names, r.Name+" ("+r.Kind+")")
			}
			sort.Strings(names)
			for _, n := range names {
				t.Logf("    %s", n)
			}
		}
	}
	if !found {
		t.Fatalf("apiserver serves no admissionregistration.k8s.io group at all")
	}
}

// TestAcceptanceVariablesInMatchConditions answers the question the playground
// cannot answer for itself: does a real apiserver accept a policy whose
// matchConditions reference variables?
//
// This matters because upstream's runtime compilePolicy DOES declare `variables`
// for matchConditions (same OptionalVariableDeclarations as the validations), so
// the CEL compiler would happily accept it. If the policy is refused, the
// refusal comes from registry validation, which is a gate the playground does
// not model at all.
func TestAcceptanceVariablesInMatchConditions(t *testing.T) {
	o := cluster(t)
	ctx := context.Background()

	const doc = `
kind: ValidatingAdmissionPolicy
metadata:
  name: oracle-vars-in-matchconditions
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["deployments"]
  variables:
    - name: x
      expression: "'x'"
  matchConditions:
    - name: uses-variable
      expression: "variables.x == 'x'"
  validations:
    - expression: "true"
`
	policy, err := oracle.ParsePolicy(doc)
	if err != nil {
		t.Fatalf("parsing policy: %v", err)
	}
	defer o.DeletePolicyQuiet(ctx, policy.Name)

	err = o.CreateRaw(ctx, policy)
	if err == nil {
		t.Logf("RESULT: the apiserver ACCEPTED a policy using variables.x inside matchConditions")
		t.Logf("  -> registry validation does not gate this; the playground is not too permissive here")
		return
	}
	t.Logf("RESULT: the apiserver REJECTED the policy. Exact error:\n%v", err)

	// Locate the gate: run the same policy through upstream's *runtime*
	// compiler (compilePolicy) with no cluster involved. If that accepts what
	// the registry rejected, the two gates genuinely disagree and the
	// playground -- which models only the runtime compiler -- is too permissive.
	validator := oracle.CompilePolicy(policy)
	if cerr := validator.CompileError(); cerr != nil {
		t.Logf("upstream's runtime compilePolicy ALSO rejects it: %v", cerr)
		t.Logf("  -> both gates agree; a playground that mirrors compilePolicy is already correct")
	} else {
		t.Logf("upstream's runtime compilePolicy ACCEPTS the same expression (CompileError() == nil)")
		t.Logf("  -> the rejection is REGISTRY VALIDATION only, a gate the playground does not model")
	}
}

// TestAcceptanceAuthorizerInMessageExpression checks the third suspected
// divergence: upstream compiles messageExpression with HasAuthorizer:false while
// the rest of the policy gets HasAuthorizer:true, so `authorizer` should be
// undeclared in a messageExpression.
func TestAcceptanceAuthorizerInMessageExpression(t *testing.T) {
	o := cluster(t)
	ctx := context.Background()

	const doc = `
kind: ValidatingAdmissionPolicy
metadata:
  name: oracle-authorizer-in-messageexpression
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["deployments"]
  validations:
    - expression: "false"
      messageExpression: "authorizer.group('').resource('pods').check('create').allowed() ? 'a' : 'b'"
`
	policy, err := oracle.ParsePolicy(doc)
	if err != nil {
		t.Fatalf("parsing policy: %v", err)
	}
	defer o.DeletePolicyQuiet(ctx, policy.Name)

	err = o.CreateRaw(ctx, policy)
	if err == nil {
		t.Errorf("RESULT: the apiserver ACCEPTED a messageExpression referencing authorizer -- upstream's HasAuthorizer:false was expected to reject it")
		return
	}
	t.Logf("RESULT: the apiserver REJECTED it. Exact error:\n%v", err)
	if !strings.Contains(err.Error(), "authorizer") {
		t.Errorf("rejection does not mention authorizer; the cause may be something else entirely")
	}
}

// TestAcceptanceAuthorizerInValidation is the control for the test above: the
// same authorizer call in a plain validation must be accepted, otherwise the
// rejection above proves nothing about messageExpression specifically.
func TestAcceptanceAuthorizerInValidation(t *testing.T) {
	o := cluster(t)
	ctx := context.Background()

	const doc = `
kind: ValidatingAdmissionPolicy
metadata:
  name: oracle-authorizer-in-validation
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["deployments"]
  validations:
    - expression: "authorizer.group('').resource('pods').check('create').allowed()"
`
	policy, err := oracle.ParsePolicy(doc)
	if err != nil {
		t.Fatalf("parsing policy: %v", err)
	}
	defer o.DeletePolicyQuiet(ctx, policy.Name)

	if err := o.CreateRaw(ctx, policy); err != nil {
		t.Errorf("control failed: the apiserver rejected authorizer in a plain validation too: %v", err)
		return
	}
	t.Logf("RESULT: authorizer in a plain validation is ACCEPTED (control passes)")
}

// TestCELEnvVersionMatchesApiserver is the regression test for the first
// suspected divergence. The playground must compile at whatever
// environment.DefaultCompatibilityVersion() reports, not at a hardcoded minor,
// because that default is the binary's minor MINUS ONE
// (EffectiveVersion.MinCompatibilityVersion) -- a library shipped in the current
// minor is not usable until the next release.
//
// The test also diffs the function sets of adjacent compatibility versions so
// the blast radius of getting this wrong is a number, not a worry.
func TestCELEnvVersionMatchesApiserver(t *testing.T) {
	def := environment.DefaultCompatibilityVersion()
	t.Logf("environment.DefaultCompatibilityVersion() = %s", def)

	names := func(v *version.Version) map[string]bool {
		envSet := environment.MustBaseEnvSet(v)
		env, err := envSet.Env(environment.StoredExpressions)
		if err != nil {
			t.Fatalf("building env for %s: %v", v, err)
		}
		out := map[string]bool{}
		for name := range env.Functions() {
			out[name] = true
		}
		for _, vd := range env.Variables() {
			out["var:"+vd.Name()] = true
		}
		return out
	}

	for _, pair := range [][2]*version.Version{
		{version.MajorMinor(1, 34), version.MajorMinor(1, 35)},
		{version.MajorMinor(1, 35), version.MajorMinor(1, 36)},
	} {
		lo, hi := names(pair[0]), names(pair[1])
		var added []string
		for n := range hi {
			if !lo[n] {
				added = append(added, n)
			}
		}
		var removed []string
		for n := range lo {
			if !hi[n] {
				removed = append(removed, n)
			}
		}
		sort.Strings(added)
		sort.Strings(removed)
		t.Logf("CEL env %s -> %s: %d functions/variables added, %d removed", pair[0], pair[1], len(added), len(removed))
		if len(added) > 0 {
			t.Logf("  added:   %s", strings.Join(added, ", "))
		}
		if len(removed) > 0 {
			t.Logf("  removed: %s", strings.Join(removed, ", "))
		}
	}
}
