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

package main_test

import (
	"os/exec"
	"strings"
	"testing"
)

// Every byte here is downloaded by every visitor, and the expensive mistakes
// are all the same shape: an innocuous-looking import whose transitive closure
// registers a scheme or a client. They are invisible in review and obvious in
// a dependency list, so this is the list.
//
// The measured example: anything whose exported signature mentions
// kubernetes.Interface re-registers the whole client-go scheme, which was
// +2.99 MB gzip when admission/plugin/policy/matching was tried.
var forbidden = []struct {
	prefix string
	why    string
}{
	{"k8s.io/client-go/kubernetes", "the typed clientset registers every built-in API group's scheme; it was measured at +2.99 MB gzip"},
	{"k8s.io/client-go/informers", "informers pull the clientset in behind them"},
	{"k8s.io/client-go/dynamic", "nothing in a browser talks to an apiserver"},
	{"k8s.io/client-go/discovery", "nothing in a browser talks to an apiserver"},
	{"google.golang.org/grpc", "egress selector and konnectivity; there is no network here"},
	{"go.opentelemetry.io/otel/exporters", "tracing exporters ship nowhere from a browser"},
	{"k8s.io/apiserver/pkg/admission/plugin/policy/validating", "+6 MB gzip; the oracle imports it, the binary must not"},
	{"k8s.io/apiserver/pkg/admission/plugin/policy/matching", "its kubernetes.Interface parameter re-registers the client-go scheme"},
	{"k8s.io/apiserver/pkg/storage", "there is nothing to store"},
	{"sigs.k8s.io/controller-runtime", "test-only; it belongs to the oracle module"},
}

func TestWasmLinksNothingExpensive(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", ".")
	cmd.Env = append(cmd.Environ(), "GOOS=js", "GOARCH=wasm")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	packages := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(packages) < 100 {
		t.Fatalf("go list -deps returned %d packages, which cannot be right", len(packages))
	}

	for _, pkg := range packages {
		for _, rule := range forbidden {
			if pkg == rule.prefix || strings.HasPrefix(pkg, rule.prefix+"/") {
				t.Errorf("the wasm binary links %s: %s", pkg, rule.why)
			}
		}
	}
	t.Logf("the wasm binary links %d packages", len(packages))
}
