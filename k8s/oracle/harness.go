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

// Package oracle runs a real kube-apiserver (via controller-runtime's envtest)
// and uses it as a differential-testing oracle for the playground's vap and
// webhook modes: it answers "what would a cluster actually do with this policy
// and this object?" with the cluster's own admission decision, message, reason
// and registry-validation errors.
//
// The package is a separate Go module so that the repository's own `go test
// ./...` never sees it (package patterns do not descend into nested modules)
// and so that controller-runtime never enters the root go.mod, which the wasm
// build depends on. Every file also carries the `oracle` build tag, so even
// building this module without `-tags oracle` yields no packages.
package oracle

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// DefaultAssetsRoot is where the README tells you to put the envtest binaries.
// It is deliberately outside the repository: the assets are ~166 MB and the
// working tree lives on a nearly full volume.
const DefaultAssetsRoot = ".local/share/kubebuilder-envtest"

// AssetsDir returns the directory holding kube-apiserver, etcd and kubectl, and
// the reason it could not be found. Exactly one of the two is non-empty.
//
// KUBEBUILDER_ASSETS wins if set (that is what `setup-envtest use -p env`
// exports). Otherwise the newest versioned directory under
// ~/.local/share/kubebuilder-envtest/k8s is used.
func AssetsDir() (dir string, skipReason string) {
	if env := os.Getenv("KUBEBUILDER_ASSETS"); env != "" {
		if err := checkAssets(env); err != nil {
			return "", fmt.Sprintf("KUBEBUILDER_ASSETS=%s is unusable: %v", env, err)
		}
		return env, ""
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Sprintf("cannot determine home directory: %v", err)
	}
	root := filepath.Join(home, DefaultAssetsRoot, "k8s")
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", fmt.Sprintf("no envtest assets: %v (run the setup-envtest command in the oracle README)", err)
	}
	var candidates []string
	for _, e := range entries {
		if e.IsDir() {
			candidates = append(candidates, e.Name())
		}
	}
	if len(candidates) == 0 {
		return "", fmt.Sprintf("no envtest assets under %s (run the setup-envtest command in the oracle README)", root)
	}
	sort.Strings(candidates)
	// Highest version last; sort.Strings is good enough for 1.3x-linux-amd64.
	dir = filepath.Join(root, candidates[len(candidates)-1])
	if err := checkAssets(dir); err != nil {
		return "", fmt.Sprintf("envtest assets at %s are incomplete: %v", dir, err)
	}
	return dir, ""
}

func checkAssets(dir string) error {
	for _, bin := range []string{"kube-apiserver", "etcd"} {
		p := filepath.Join(dir, bin)
		info, err := os.Stat(p)
		if err != nil {
			return err
		}
		if info.Mode()&0o111 == 0 {
			return fmt.Errorf("%s is not executable", p)
		}
	}
	return nil
}

// Oracle is a running control plane plus the clients needed to interrogate it.
type Oracle struct {
	Env       *envtest.Environment
	Cfg       *rest.Config
	Clientset *kubernetes.Clientset
	Dynamic   dynamic.Interface
	Discovery discovery.DiscoveryInterface
	Mapper    *restmapper.DeferredDiscoveryRESTMapper

	// StartupDuration is how long Env.Start() took, reported by the suite so
	// the cost of the oracle is visible rather than folklore.
	StartupDuration time.Duration
	AssetsDir       string
}

// Start boots etcd + kube-apiserver and builds the clients. The caller must
// call Stop. Start does not consult testing.T so that it can be used from
// TestMain.
func Start(ctx context.Context) (*Oracle, error) {
	dir, skip := AssetsDir()
	if skip != "" {
		return nil, fmt.Errorf("%s", skip)
	}

	env := &envtest.Environment{
		BinaryAssetsDirectory: dir,
		// The apiserver's defaults already enable both the
		// ValidatingAdmissionPolicy and ValidatingAdmissionWebhook admission
		// plugins; envtest only disables ServiceAccount. Nothing else needs to
		// be turned on for the modes the playground models.
		ControlPlaneStartTimeout: 2 * time.Minute,
		ControlPlaneStopTimeout:  time.Minute,
	}

	started := time.Now()
	cfg, err := env.Start()
	if err != nil {
		return nil, fmt.Errorf("starting envtest control plane from %s: %w", dir, err)
	}
	elapsed := time.Since(started)

	o := &Oracle{Env: env, Cfg: cfg, StartupDuration: elapsed, AssetsDir: dir}

	// The oracle hammers the apiserver with polling loops; the default client
	// QPS of 5 turns a two second readiness wait into a thirty second one.
	clientCfg := rest.CopyConfig(cfg)
	clientCfg.QPS = 200
	clientCfg.Burst = 400

	if o.Clientset, err = kubernetes.NewForConfig(clientCfg); err != nil {
		_ = env.Stop()
		return nil, fmt.Errorf("building clientset: %w", err)
	}
	if o.Dynamic, err = dynamic.NewForConfig(clientCfg); err != nil {
		_ = env.Stop()
		return nil, fmt.Errorf("building dynamic client: %w", err)
	}
	disco, err := discovery.NewDiscoveryClientForConfig(clientCfg)
	if err != nil {
		_ = env.Stop()
		return nil, fmt.Errorf("building discovery client: %w", err)
	}
	o.Discovery = disco
	o.Mapper = restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(disco))

	// Fail loudly here rather than in the first test: if the apiserver is up
	// but not serving discovery, nothing below will make sense.
	if _, err := o.Clientset.Discovery().ServerVersion(); err != nil {
		_ = env.Stop()
		return nil, fmt.Errorf("apiserver did not answer /version: %w", err)
	}
	return o, nil
}

// Stop tears down the control plane.
func (o *Oracle) Stop() error {
	if o == nil || o.Env == nil {
		return nil
	}
	return o.Env.Stop()
}
