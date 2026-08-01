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

package k8s_test

import (
	"testing"

	"github.com/undistro/cel-playground/k8s"
)

func TestProbeSiblings(t *testing.T) {
	runM := func(name string, policy string) {
		t.Run("MAP/"+name, func(t *testing.T) {
			out, err := k8s.EvalMutatingAdmissionPolicy([]byte(policy), nil, []byte(probeDeployment), nil, nil, nil)
			probePrint(t, "MAP "+name, out, err)
		})
	}
	runV := func(name string, policy string) {
		t.Run("VAP/"+name, func(t *testing.T) {
			out, err := k8s.EvalValidatingAdmissionPolicy([]byte(policy), nil, []byte(probeDeployment), nil, nil, nil)
			probePrint(t, "VAP "+name, out, err)
		})
	}

	// VAP twin of the Conditional Mutation example
	runV("conditional", `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: probe
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
    - apiGroups: ["apps"]
      apiVersions: ["v1"]
      operations: ["CREATE"]
      resources: ["deployments"]
  matchConditions:
  - name: tier-not-set
    expression: "!has(object.metadata.labels) || !('tier' in object.metadata.labels)"
  variables:
  - name: appName
    expression: "object.metadata.labels['app']"
  validations:
  - expression: "variables.appName == 'nginx'"
    message: "app must be nginx"
`)

	// MAP whose matchConditions name variables
	runM("matchcondition-uses-variables", `
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata:
  name: probe
spec:
  failurePolicy: Fail
  variables:
  - name: appName
    expression: "object.metadata.labels['app']"
  matchConditions:
  - name: named
    expression: "variables.appName == 'nginx'"
  mutations:
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{metadata: Object.metadata{labels: {"x": "y"}}}
`)

	// matchCondition false: mutations should not run
	runM("matchcondition-false", `
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata:
  name: probe
spec:
  failurePolicy: Fail
  matchConditions:
  - name: never
    expression: "object.metadata.name == 'other'"
  mutations:
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{metadata: Object.metadata{labels: {"x": "y"}}}
`)

	// matchCondition errors under Fail
	runM("matchcondition-error-fail", `
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata:
  name: probe
spec:
  failurePolicy: Fail
  matchConditions:
  - name: broken
    expression: "object.spec.missing == 'x'"
  mutations:
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{metadata: Object.metadata{labels: {"x": "y"}}}
`)

	// VAP pasted into MAP mode error text
	runM("vap-in-map-mode", `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: probe
spec:
  validations:
  - expression: "true"
`)

	// MAP pasted into VAP mode error text
	runV("map-in-vap-mode", `
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata:
  name: probe
spec:
  mutations:
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: "Object{}"
`)

	// object typed with a wrong field (schema warning path)
	t.Run("MAP/object-misfits-schema", func(t *testing.T) {
		out, err := k8s.EvalMutatingAdmissionPolicy([]byte(`
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata:
  name: probe
spec:
  mutations:
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{metadata: Object.metadata{labels: {"x": "y"}}}
`), nil, []byte(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  replicas: "10"
`), nil, nil, nil)
		probePrint(t, "object-misfits-schema", out, err)
	})

	// JSONPatch that writes a quoted number into replicas (readback check)
	t.Run("MAP/jsonpatch-quoted-replicas", func(t *testing.T) {
		out, err := k8s.EvalMutatingAdmissionPolicy([]byte(`
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata:
  name: probe
spec:
  failurePolicy: Ignore
  mutations:
  - patchType: JSONPatch
    jsonPatch:
      expression: >
        [JSONPatch{op: "replace", path: "/spec/replicas", value: "10"}]
`), nil, []byte(probeDeployment), nil, nil, nil)
		probePrint(t, "jsonpatch-quoted-replicas", out, err)
	})
}
