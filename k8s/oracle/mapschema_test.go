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
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	"github.com/undistro/cel-playground/k8s"
)

// TestMergeSemanticsMatchTheCluster is the evidence that the 387 KB of schema
// the binary embeds describes the same merge a cluster performs.
//
// TestBuiltinSchemaIsCurrent proves the embedded copy equals client-go's. This
// is the other half: that what client-go generates and what the apiserver
// serves from /openapi/v3 agree about the markers that decide a merge. They
// have a common origin -- both are generated from the +listType, +listMapKey
// and +structType markers on the k8s.io/api Go types -- but a common origin is
// not a checked equivalence, and the merge is the thing the mode exists to
// show.
//
// Each case is an applyConfiguration whose answer depends on a marker: a keyed
// list merges by key, an atomic one is refused outright by upstream's
// validatePatch, and a granular map merges key by key. The playground's answer
// has to be the cluster's, refusals included.
func TestMergeSemanticsMatchTheCluster(t *testing.T) {
	o := cluster(t)

	cases := []struct {
		name string
		// object is the resource as submitted.
		object string
		// mutation is the applyConfiguration expression.
		mutation string
		// probes are the dotted paths whose merged value has to agree.
		probes []string
	}{{
		// listType=map keyed by port+protocol: the existing entry survives.
		name: "Service.spec.ports merges by key",
		object: `apiVersion: v1
kind: Service
metadata: {name: PLACEHOLDER, namespace: default}
spec:
  selector: {app: x}
  ports:
    - {name: http, port: 80, protocol: TCP, targetPort: 8080}
    - {name: grpc, port: 90, protocol: TCP, targetPort: 9090}
`,
		mutation: `Object{spec: Object.spec{ports: [Object.spec.ports{name: "metrics", port: 9100, protocol: "TCP"}]}}`,
		probes:   []string{".spec.ports"},
	}, {
		// The same key already present: merged into, not appended.
		name: "Service.spec.ports merges into an existing key",
		object: `apiVersion: v1
kind: Service
metadata: {name: PLACEHOLDER, namespace: default}
spec:
  selector: {app: x}
  ports:
    - {name: http, port: 80, protocol: TCP, targetPort: 8080}
`,
		mutation: `Object{spec: Object.spec{ports: [Object.spec.ports{port: 80, protocol: "TCP", name: "renamed"}]}}`,
		probes:   []string{".spec.ports"},
	}, {
		name: "Deployment volumes and container env merge by name",
		object: `apiVersion: apps/v1
kind: Deployment
metadata: {name: PLACEHOLDER, namespace: default}
spec:
  selector: {matchLabels: {app: x}}
  template:
    metadata: {labels: {app: x}}
    spec:
      volumes:
        - {name: existing, emptyDir: {}}
      containers:
        - name: app
          image: nginx
          env:
            - {name: KEEP, value: "1"}
`,
		mutation: `Object{spec: Object.spec{template: Object.spec.template{spec: Object.spec.template.spec{
			volumes: [Object.spec.template.spec.volumes{name: "added", emptyDir: Object.spec.template.spec.volumes.emptyDir{}}],
			containers: [Object.spec.template.spec.containers{
				name: "app",
				env: [Object.spec.template.spec.containers.env{name: "ADDED", value: "2"}]
			}]
		}}}}`,
		probes: []string{".spec.template.spec.volumes", ".spec.template.spec.containers"},
	}, {
		// resources.limits is a granular map: one key merges without
		// disturbing the others.
		name: "container resource limits merge key by key",
		object: `apiVersion: apps/v1
kind: Deployment
metadata: {name: PLACEHOLDER, namespace: default}
spec:
  selector: {matchLabels: {app: x}}
  template:
    metadata: {labels: {app: x}}
    spec:
      containers:
        - name: app
          image: nginx
          resources:
            limits: {cpu: "1"}
`,
		mutation: `Object{spec: Object.spec{template: Object.spec.template{spec: Object.spec.template.spec{
			containers: [Object.spec.template.spec.containers{
				name: "app",
				resources: Object.spec.template.spec.containers.resources{limits: {"memory": "1Gi"}}
			}]
		}}}}`,
		probes: []string{".spec.template.spec.containers"},
	}, {
		// tolerations carries no list marker, so it is atomic and upstream's
		// validatePatch refuses to touch it. Both sides have to refuse.
		name: "an atomic list is refused",
		object: `apiVersion: apps/v1
kind: Deployment
metadata: {name: PLACEHOLDER, namespace: default}
spec:
  selector: {matchLabels: {app: x}}
  template:
    metadata: {labels: {app: x}}
    spec:
      containers: [{name: app, image: nginx}]
`,
		mutation: `Object{spec: Object.spec{template: Object.spec.template{spec: Object.spec.template.spec{
			tolerations: [Object.spec.template.spec.tolerations{key: "k", operator: "Exists"}]
		}}}}`,
		probes: nil,
	}, {
		// nodeSelector is an atomic map, refused for the same reason.
		name: "an atomic map is refused",
		object: `apiVersion: apps/v1
kind: Deployment
metadata: {name: PLACEHOLDER, namespace: default}
spec:
  selector: {matchLabels: {app: x}}
  template:
    metadata: {labels: {app: x}}
    spec:
      containers: [{name: app, image: nginx}]
`,
		mutation: `Object{spec: Object.spec{template: Object.spec.template{spec: Object.spec.template.spec{
			nodeSelector: {"disk": "ssd"}
		}}}}`,
		probes: nil,
	}}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			marker := mapPolicyName("map-schema-" + string(rune('a'+i)))
			policy := parseMAP(t, `
metadata:
  name: `+marker+`
spec:
  failurePolicy: Fail
  reinvocationPolicy: Never
  matchConstraints:
    resourceRules:
      - apiGroups: ["", "apps"]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["services", "deployments"]
  mutations:
    - patchType: ApplyConfiguration
      applyConfiguration:
        expression: >
          `+strings.ReplaceAll(tc.mutation, "\n", " ")+`
`)
			binding := parseMAPBinding(t, bindingYAML(marker, marker, "yes"))

			submitted := func(name string) *unstructured.Unstructured {
				var content map[string]any
				if err := yaml.Unmarshal([]byte(strings.ReplaceAll(tc.object, "PLACEHOLDER", name)), &content); err != nil {
					t.Fatalf("loading the object: %v", err)
				}
				object := &unstructured.Unstructured{Object: content}
				labels := object.GetLabels()
				if labels == nil {
					labels = map[string]string{}
				}
				labels[marker] = "yes"
				object.SetLabels(labels)
				return object
			}

			if err := installMAP(t, o, policy, binding); err != nil {
				t.Fatalf("installing the policy: %v", err)
			}
			waitMAPActive(t, o)

			fromCluster, clusterErr := dryRunCreateObject(o, submitted(marker+"-dep"))

			playgroundObject, err := yaml.Marshal(submitted(marker + "-dep"))
			if err != nil {
				t.Fatalf("serialising the object: %v", err)
			}
			// parseMAP leaves TypeMeta empty, and the playground reads the
			// document the way a cluster does: kind first.
			stored := policy.DeepCopy()
			stored.APIVersion = "admissionregistration.k8s.io/v1"
			stored.Kind = "MutatingAdmissionPolicy"
			policyYAML, err := yaml.Marshal(stored)
			if err != nil {
				t.Fatalf("serialising the policy: %v", err)
			}
			response := runPlaygroundEval(t, policyYAML, playgroundObject)

			if len(tc.probes) == 0 {
				// The refusal cases. Both sides have to refuse, and for the
				// same reason: structured-merge-diff's own wording.
				if clusterErr == nil {
					t.Fatalf("the cluster applied a patch to an atomic field: %s", pretty(fromCluster.Object))
				}
				if !response.Mutations[0].IsError {
					t.Fatalf("the playground applied it and the cluster refused it:\n%v", clusterErr)
				}
				if !sharesReason(*response.Mutations[0].Error, clusterErr.Error()) {
					t.Errorf("refused for different reasons\n  playground: %s\n  cluster:    %v", *response.Mutations[0].Error, clusterErr)
				}
				t.Logf("both refused: %s", *response.Mutations[0].Error)
				return
			}

			if clusterErr != nil {
				t.Fatalf("the cluster refused the request: %v", clusterErr)
			}
			if response.Mutations[0].IsError {
				t.Fatalf("the playground refused it and the cluster applied it: %s", *response.Mutations[0].Error)
			}
			var merged map[string]any
			if err := yaml.Unmarshal([]byte(response.FinalObject), &merged); err != nil {
				t.Fatalf("decoding the playground's object: %v", err)
			}
			for _, path := range tc.probes {
				want, _ := valueAt(fromCluster.Object, path)
				got, _ := valueAt(merged, path)
				if err := containedIn(got, want); err != nil {
					t.Errorf("%s: %v\n  cluster:    %s\n  playground: %s", path, err, pretty(want), pretty(got))
					continue
				}
				t.Logf("%s agrees (%d entries)", path, length(got))
			}
		})
	}
}

func length(value any) int {
	if list, ok := value.([]any); ok {
		return len(list)
	}
	return 1
}

func runPlaygroundEval(t *testing.T, policy, object []byte) k8s.EvalResponse {
	t.Helper()
	out, err := k8s.EvalMutatingAdmissionPolicy(policy, nil, object, nil, nil, nil)
	if err != nil {
		t.Fatalf("the playground refused the policy: %v", err)
	}
	return decodeEvalResponse(t, out)
}
