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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/undistro/cel-playground/k8s/oracle"
)

// TestMAPRuntimeConfigVersions starts a SECOND apiserver with the alpha and
// beta admissionregistration groupVersions explicitly turned on, to establish
// whether v1alpha1/v1beta1 MutatingAdmissionPolicy is merely off by default at
// 1.36.2 or gone from the binary.
//
// The default control plane the rest of this package uses is untouched; this
// one is started and stopped inside the test.
func TestMAPRuntimeConfigVersions(t *testing.T) {
	dir, skip := oracle.AssetsDir()
	if skip != "" {
		t.Skipf("no envtest assets: %s", skip)
	}

	cases := []struct {
		name         string
		runtimeCfg   []string
		featureGates []string
	}{
		{name: "defaults"},
		{
			name:       "runtime-config alpha+beta, no gate flag",
			runtimeCfg: []string{"admissionregistration.k8s.io/v1alpha1=true", "admissionregistration.k8s.io/v1beta1=true"},
		},
		{
			name:         "gate explicitly off",
			featureGates: []string{"MutatingAdmissionPolicy=false"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := &envtest.Environment{
				BinaryAssetsDirectory:    dir,
				ControlPlaneStartTimeout: 2 * time.Minute,
				ControlPlaneStopTimeout:  time.Minute,
			}
			args := env.ControlPlane.GetAPIServer().Configure()
			if len(tc.runtimeCfg) > 0 {
				args.Append("runtime-config", tc.runtimeCfg...)
			}
			if len(tc.featureGates) > 0 {
				args.Append("feature-gates", tc.featureGates...)
			}

			cfg, err := env.Start()
			if err != nil {
				t.Fatalf("starting control plane: %v", err)
			}
			defer func() {
				if err := env.Stop(); err != nil {
					t.Errorf("stopping: %v", err)
				}
			}()

			disco, err := discovery.NewDiscoveryClientForConfig(cfg)
			if err != nil {
				t.Fatalf("discovery client: %v", err)
			}
			groups, err := disco.ServerGroups()
			if err != nil {
				t.Fatalf("server groups: %v", err)
			}
			for _, g := range groups.Groups {
				if g.Name != "admissionregistration.k8s.io" {
					continue
				}
				for _, v := range g.Versions {
					list, err := disco.ServerResourcesForGroupVersion(v.GroupVersion)
					if err != nil {
						t.Errorf("listing %s: %v", v.GroupVersion, err)
						continue
					}
					var names []string
					for _, r := range list.APIResources {
						if strings.Contains(r.Name, "/") {
							continue
						}
						names = append(names, r.Name)
					}
					sort.Strings(names)
					t.Logf("%s: %s", v.GroupVersion, strings.Join(names, ", "))
				}
			}

			// Does a policy actually mutate on this control plane?
			clientCfg := rest.CopyConfig(cfg)
			clientCfg.QPS, clientCfg.Burst = 200, 400
			cs, err := kubernetes.NewForConfig(clientCfg)
			if err != nil {
				t.Fatalf("clientset: %v", err)
			}
			dyn, err := dynamic.NewForConfig(clientCfg)
			if err != nil {
				t.Fatalf("dynamic client: %v", err)
			}
			ctx := context.Background()
			policy := parseMAP(t, mapPolicyYAML("rc-probe", "Never", "",
				`[JSONPatch{op: "add", path: "/data/mutated", value: "yes"}]`))
			if _, err := cs.AdmissionregistrationV1().MutatingAdmissionPolicies().Create(ctx, policy, metav1.CreateOptions{}); err != nil {
				t.Fatalf("creating the probe policy: %v", err)
			}
			binding := parseMAPBinding(t, bindingYAML("rc-probe", "rc", "yes"))
			if _, err := cs.AdmissionregistrationV1().MutatingAdmissionPolicyBindings().Create(ctx, binding, metav1.CreateOptions{}); err != nil {
				t.Fatalf("creating the probe binding: %v", err)
			}

			probe := labelled(cm("rc-probe-cm", map[string]any{"seed": "1"}), "rc", "yes")
			deadline := time.Now().Add(20 * time.Second)
			mutated := false
			for time.Now().Before(deadline) {
				out, err := dyn.Resource(configMapGVR).Namespace("default").
					Create(ctx, probe, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
				if err == nil {
					d, _, _ := unstructured.NestedStringMap(out.Object, "data")
					if d["mutated"] == "yes" {
						mutated = true
						break
					}
				}
				time.Sleep(200 * time.Millisecond)
			}
			t.Logf("mutation observed within 20s: %v", mutated)
		})
	}
}
