package k8s_test

import (
	"testing"

	"github.com/undistro/cel-playground/k8s"
)

func TestProbeEmptyList(t *testing.T) {
	run := func(name, expr string) {
		t.Run(name, func(t *testing.T) {
			out, err := k8s.EvalMutatingAdmissionPolicy([]byte(`
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionPolicy
metadata:
  name: probe
spec:
  mutations:
  - patchType: JSONPatch
    jsonPatch:
      expression: '`+expr+`'
`), nil, []byte(probeDeployment), nil, nil, nil)
			probePrint(t, name, out, err)
		})
	}
	run("bare-empty-list", `[]`)
	run("conditional-empty-list", `object.metadata.name == "other" ? [JSONPatch{op: "add", path: "/metadata/labels/x", value: "y"}] : []`)
}
