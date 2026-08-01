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
	"fmt"
	"os"
	"testing"

	"github.com/undistro/cel-playground/k8s/oracle"
)

// One control plane is shared by every test in the package: starting etcd and
// kube-apiserver costs seconds, and nothing here mutates cluster-wide state
// that is not cleaned up per test.
var (
	shared     *oracle.Oracle
	skipReason string
)

func TestMain(m *testing.M) {
	dir, skip := oracle.AssetsDir()
	if skip != "" {
		// Not a failure: the in-process tests still run, and the envtest-backed
		// ones skip with this reason. This is what keeps the suite usable on a
		// machine that has never downloaded the assets.
		skipReason = skip
		os.Exit(m.Run())
	}
	fmt.Printf("oracle: using envtest assets from %s\n", dir)

	var err error
	shared, err = oracle.Start(context.Background())
	if err != nil {
		// A present-but-broken control plane must fail loudly rather than skip.
		fmt.Fprintf(os.Stderr, "oracle: FAILED to start control plane: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("oracle: control plane up in %s (kube-apiserver + etcd)\n", shared.StartupDuration)

	code := m.Run()

	if err := shared.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "oracle: control plane did not stop cleanly: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

// cluster returns the shared control plane, skipping the test when the envtest
// assets are not installed.
func cluster(t *testing.T) *oracle.Oracle {
	t.Helper()
	if shared == nil {
		t.Skipf("no kube-apiserver oracle available: %s", skipReason)
	}
	return shared
}
