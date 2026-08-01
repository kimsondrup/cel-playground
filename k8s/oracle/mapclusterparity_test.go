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
	"fmt"
	"sort"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	"github.com/undistro/cel-playground/k8s/oracle"
)

// TestMAPPlaygroundMatchesCluster submits the shipped fixtures to a real
// kube-apiserver and holds the playground's answer to what the cluster
// actually did.
//
// The cluster's object cannot be compared wholesale: it has also been through
// decoding, defaulting and the rest of the admission chain, none of which the
// playground runs. What isolates the policy is submitting the same object twice
// -- once with the binding in place and once without -- and taking the paths
// where the two differ. Those, and only those, are the policy's doing, and the
// playground has to agree on every one of them.
//
// It is a dry-run CREATE both times, so the apiserver runs the whole admission
// chain and stores nothing.
func TestMAPPlaygroundMatchesCluster(t *testing.T) {
	o := cluster(t)

	cases := []struct {
		name   string
		policy string
		object string
	}{
		// The flagship: initContainers is listType=map keyed by name, so a
		// cluster merges the injected sidecar in beside the existing one. Get
		// the merge schema wrong and "setup" disappears.
		{"sidecar", "sidecar policy.yaml", "sidecar object.yaml"},
		{"applyconfig label", "applyconfig label policy.yaml", "object.yaml"},
		{"jsonpatch ops", "jsonpatch ops policy.yaml", "object.yaml"},
		{"chained", "chained policy.yaml", "object.yaml"},
		{"variables", "variables policy.yaml", "object.yaml"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			marker := "map-parity-" + mapPolicyName(tc.name)
			policy, err := oracle.LoadMutatingPolicy(oracle.MapFixture(tc.policy))
			if err != nil {
				t.Fatalf("loading the policy: %v", err)
			}
			policy.Name = marker
			// Every fixture's matchConstraints already select apps/v1
			// deployments, but some declare none at all, which the registry
			// refuses. Supplying one keeps the fixture the thing under test.
			if policy.Spec.MatchConstraints == nil {
				policy.Spec.MatchConstraints = deploymentConstraints()
			}
			binding := parseMAPBinding(t, bindingYAML(marker, marker, "yes"))

			object, err := oracle.LoadUnstructured(oracle.MapFixture(tc.object))
			if err != nil {
				t.Fatalf("loading the object: %v", err)
			}

			// Both runs carry the label the binding selects on, so the only
			// difference between them is the policy. The unbound one is made
			// before the policy exists rather than by withholding the label: a
			// selector that silently failed to match would otherwise make the two
			// runs identical and the comparison vacuous.
			selected := func(name string) *unstructured.Unstructured {
				copied := named(object, name)
				labels := copied.GetLabels()
				if labels == nil {
					labels = map[string]string{}
				}
				labels[marker] = "yes"
				copied.SetLabels(labels)
				return copied
			}

			baseline, err := dryRunCreateObject(o, selected(marker+"-baseline"))
			if err != nil {
				t.Fatalf("the cluster refused the unmutated object: %v", err)
			}

			if err := installMAP(t, o, policy, binding); err != nil {
				t.Fatalf("installing the policy: %v", err)
			}
			waitMAPActive(t, o)

			mutated, err := dryRunCreateObject(o, selected(marker+"-mutated"))
			if err != nil {
				t.Fatalf("the cluster refused the mutated object: %v", err)
			}

			changed := changedPaths(baseline.Object, mutated.Object)
			// The name is the one thing that has to differ between two dry runs.
			changed = without(changed, ".metadata.name")
			if len(changed) == 0 {
				t.Fatalf("the policy changed nothing on the cluster: the binding did not select the object, so this case proves nothing")
			}
			t.Logf("the cluster's policy changed: %v", changed)

			var playground map[string]any
			if err := yaml.Unmarshal([]byte(runPlaygroundMutation(t, mapParityCase{
				policy: tc.policy, object: tc.object,
			}).FinalObject), &playground); err != nil {
				t.Fatalf("decoding the playground's object: %v", err)
			}

			for _, path := range changed {
				want, wantFound := valueAt(mutated.Object, path)
				got, gotFound := valueAt(playground, path)
				if wantFound != gotFound {
					t.Errorf("%s: the cluster %s it and the playground %s", path, present(wantFound), present(gotFound))
					continue
				}
				if err := containedIn(got, want); err != nil {
					t.Errorf("%s: %v\n  cluster:    %s\n  playground: %s", path, err, pretty(want), pretty(got))
				}
			}
		})
	}
}

func present(found bool) string {
	if found {
		return "has"
	}
	return "does not have"
}

func mapPolicyName(name string) string {
	out := make([]rune, 0, len(name))
	for _, r := range name {
		if r == ' ' {
			r = '-'
		}
		out = append(out, r)
	}
	return string(out)
}

func named(object *unstructured.Unstructured, name string) *unstructured.Unstructured {
	copied := object.DeepCopy()
	copied.SetName(name)
	return copied
}

func deploymentConstraints() *admissionregistrationv1.MatchResources {
	return &admissionregistrationv1.MatchResources{
		ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{{
			RuleWithOperations: admissionregistrationv1.RuleWithOperations{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   []string{"apps"},
					APIVersions: []string{"v1"},
					Resources:   []string{"deployments"},
				},
			},
		}},
	}
}

func without(paths []string, drop ...string) []string {
	kept := paths[:0:0]
	for _, path := range paths {
		skip := false
		for _, d := range drop {
			if path == d {
				skip = true
				break
			}
		}
		if !skip {
			kept = append(kept, path)
		}
	}
	return kept
}

// changedPaths returns every dotted path at which two decoded objects differ,
// stopping at the first level where they do rather than descending into a value
// that is wholly new. Lists are compared as a whole: a merge that reorders or
// replaces one is exactly what this has to notice.
func changedPaths(before, after map[string]any) []string {
	var paths []string
	var walk func(prefix string, a, b map[string]any)
	walk = func(prefix string, a, b map[string]any) {
		keys := map[string]struct{}{}
		for key := range a {
			keys[key] = struct{}{}
		}
		for key := range b {
			keys[key] = struct{}{}
		}
		ordered := make([]string, 0, len(keys))
		for key := range keys {
			ordered = append(ordered, key)
		}
		sort.Strings(ordered)
		for _, key := range ordered {
			path := prefix + "." + key
			left, leftOK := a[key]
			right, rightOK := b[key]
			if leftOK && rightOK {
				leftMap, leftIsMap := left.(map[string]any)
				rightMap, rightIsMap := right.(map[string]any)
				if leftIsMap && rightIsMap {
					walk(path, leftMap, rightMap)
					continue
				}
				if pretty(left) == pretty(right) {
					continue
				}
			}
			paths = append(paths, path)
		}
	}
	walk("", before, after)
	// Timestamps and identity differ between two creates whatever the policy
	// does.
	return without(paths,
		".metadata.creationTimestamp", ".metadata.uid", ".metadata.resourceVersion",
		".metadata.generation", ".metadata.managedFields", ".status")
}

// containedIn reports whether everything the playground says about a value is
// what the cluster says about it.
//
// Not equality: the cluster defaults the object and the playground does not, so
// a container the policy injected comes back from the cluster carrying
// imagePullPolicy, resources and terminationMessagePath as well. Those are the
// documented difference. Every field the playground does set has to match, and
// a list has to have the same length and the same order -- which is what makes
// a keyed list merged wrongly, or reordered, a failure rather than a subset.
func containedIn(got, want any) error {
	switch got := got.(type) {
	case map[string]any:
		wantMap, ok := want.(map[string]any)
		if !ok {
			return fmt.Errorf("the playground has an object where the cluster has %T", want)
		}
		keys := make([]string, 0, len(got))
		for key := range got {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value, ok := wantMap[key]
			if !ok {
				return fmt.Errorf("the playground sets %s, which the cluster does not", key)
			}
			if err := containedIn(got[key], value); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
		}
		return nil
	case []any:
		wantList, ok := want.([]any)
		if !ok {
			return fmt.Errorf("the playground has a list where the cluster has %T", want)
		}
		if len(got) != len(wantList) {
			return fmt.Errorf("the playground has %d entries and the cluster %d", len(got), len(wantList))
		}
		for i := range got {
			if err := containedIn(got[i], wantList[i]); err != nil {
				return fmt.Errorf("[%d]: %w", i, err)
			}
		}
		return nil
	default:
		if pretty(got) != pretty(want) {
			return fmt.Errorf("%s where the cluster has %s", pretty(got), pretty(want))
		}
		return nil
	}
}

// valueAt reads a dotted path out of a decoded object.
func valueAt(object map[string]any, path string) (any, bool) {
	cursor := any(object)
	for _, key := range splitPath(path) {
		asMap, ok := cursor.(map[string]any)
		if !ok {
			return nil, false
		}
		cursor, ok = asMap[key]
		if !ok {
			return nil, false
		}
	}
	return cursor, true
}

func splitPath(path string) []string {
	var keys []string
	current := ""
	for _, r := range path[1:] {
		if r == '.' {
			keys = append(keys, current)
			current = ""
			continue
		}
		current += string(r)
	}
	return append(keys, current)
}
