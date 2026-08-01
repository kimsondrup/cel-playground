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
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/undistro/cel-playground/k8s"
	sigsyaml "sigs.k8s.io/yaml"
)

type probeExample struct {
	Name          string `json:"name"`
	Map           string `json:"map"`
	DataOldObject string `json:"dataOldObject"`
	DataObject    string `json:"dataObject"`
	DataNamespace string `json:"dataNamespace"`
	DataRequest   string `json:"dataRequest"`
	DataAuth      string `json:"dataAuthorizer"`
}

func probePrint(t *testing.T, name string, out string, err error) {
	t.Helper()
	t.Logf("===== %s =====", name)
	if err != nil {
		t.Logf("TOP-LEVEL ERROR: %v", err)
		return
	}
	var buf bytes.Buffer
	if e := json.Indent(&buf, []byte(out), "", "  "); e != nil {
		t.Logf("RAW: %s", out)
		return
	}
	t.Logf("\n%s", buf.String())
}

func TestProbeExamples(t *testing.T) {
	raw, err := os.ReadFile("../mutating_examples.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Examples []probeExample `json:"examples"`
	}
	if err := sigsyaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, ex := range doc.Examples {
		t.Run(ex.Name, func(t *testing.T) {
			out, err := k8s.EvalMutatingAdmissionPolicy(
				[]byte(ex.Map), []byte(ex.DataOldObject), []byte(ex.DataObject),
				[]byte(ex.DataNamespace), []byte(ex.DataRequest), []byte(ex.DataAuth))
			probePrint(t, "MAP "+ex.Name, out, err)
		})
	}
}

const probeDeployment = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
  namespace: default
  labels:
    app: nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.27
`

func probePolicy(mutations string, extra string) []byte {
	return []byte(`
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata:
  name: probe
spec:
  failurePolicy: Fail
` + extra + `
  mutations:
` + mutations)
}

const labelMutation = `
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{metadata: Object.metadata{labels: {"k%d": "v"}}}
`

func TestProbeScenarios(t *testing.T) {
	run := func(name string, policy, object []byte) {
		t.Run(name, func(t *testing.T) {
			out, err := k8s.EvalMutatingAdmissionPolicy(policy, nil, object, nil, nil, nil)
			probePrint(t, name, out, err)
		})
	}

	// several mutations, third fails
	run("third-of-four-fails", probePolicy(`
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{metadata: Object.metadata{labels: {"one": "1"}}}
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{metadata: Object.metadata{labels: {"two": "2"}}}
  - patchType: JSONPatch
    jsonPatch:
      expression: >
        [JSONPatch{op: "replace", path: "/spec/missing/deeply", value: 1}]
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{metadata: Object.metadata{labels: {"four": "4"}}}
`, ""), []byte(probeDeployment))

	// Object{} unchanged
	run("empty-object-unchanged", probePolicy(`
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: "Object{}"
`, ""), []byte(probeDeployment))

	// ConfigMap
	run("configmap", probePolicy(`
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{data: {"injected": "yes"}}
`, ""), []byte(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: cm
  namespace: default
data:
  a: "1"
`))

	// Service
	run("service", probePolicy(`
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{metadata: Object.metadata{annotations: {"probe": "yes"}}}
`, ""), []byte(`
apiVersion: v1
kind: Service
metadata:
  name: svc
  namespace: default
spec:
  selector:
    app: nginx
  ports:
  - port: 80
    targetPort: 8080
`))

	// Pod
	run("pod", probePolicy(`
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{spec: Object.spec{nodeSelector: {"disktype": "ssd"}}}
`, ""), []byte(`
apiVersion: v1
kind: Pod
metadata:
  name: p
  namespace: default
spec:
  containers:
  - name: c
    image: nginx:1.27
`))

	// object with status filled in
	run("object-with-status", probePolicy(`
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{metadata: Object.metadata{labels: {"probe": "yes"}}}
`, ""), []byte(probeDeployment+`
status:
  replicas: 1
  readyReplicas: 1
  availableReplicas: 1
  observedGeneration: 2
  conditions:
  - type: Available
    status: "True"
`))

	// failurePolicy Ignore, one broken mutation
	run("ignore-broken", []byte(`
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata:
  name: probe
spec:
  failurePolicy: Ignore
  mutations:
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{metadata: Object.metadata{labels: {"good": "yes"}}}
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{metadata: Object.metadata{labels: {"boom": string(object.spec.nonexistent)}}}
`), []byte(probeDeployment))

	// JSONPatch remove of absent path
	run("jsonpatch-remove-absent", probePolicy(`
  - patchType: JSONPatch
    jsonPatch:
      expression: >
        [JSONPatch{op: "remove", path: "/metadata/annotations/nope"}]
`, ""), []byte(probeDeployment))

	// CRD object
	run("crd-applyconfig", probePolicy(`
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >
        Object{spec: Object.spec{size: 3}}
`, ""), []byte(`
apiVersion: example.com/v1
kind: Widget
metadata:
  name: w
  namespace: default
spec:
  size: 1
`))

	run("crd-jsonpatch", probePolicy(`
  - patchType: JSONPatch
    jsonPatch:
      expression: >
        [JSONPatch{op: "replace", path: "/spec/size", value: 3}]
`, ""), []byte(`
apiVersion: example.com/v1
kind: Widget
metadata:
  name: w
  namespace: default
spec:
  size: 1
`))

	// fifteen mutations
	fifteen := ""
	for i := 0; i < 15; i++ {
		fifteen += "\n  - patchType: ApplyConfiguration\n    applyConfiguration:\n      expression: >\n        Object{metadata: Object.metadata{labels: {\"k" + string(rune('a'+i)) + "\": \"v\"}}}"
	}
	run("fifteen-mutations", probePolicy(fifteen, ""), []byte(probeDeployment))
}
