// Copyright 2023 Undistro Authors
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

package k8s

import (
	"errors"
	"slices"
	"sort"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"k8s.io/client-go/applyconfigurations"
	"k8s.io/client-go/kubernetes/scheme"
	smdschema "sigs.k8s.io/structured-merge-diff/v6/schema"
	"sigs.k8s.io/structured-merge-diff/v6/typed"
)

// ApplyConfiguration mutations are applied with server-side-apply merge
// semantics, which need the schema of the target type: without one, a list such
// as spec.template.spec.initContainers (x-kubernetes-list-type=map, keyed by
// name) is *replaced* rather than merged by name, and a sidecar-injection
// policy silently drops the containers that were already there.
//
// A cluster always has a schema -- the apiserver serves one for every
// registered type from /openapi/v3 -- so a mutation that merges by key on a
// cluster has to merge by key here too, or the playground misreports the thing
// it exists to demonstrate.
//
// The playground has no cluster to ask, so it uses the structured-merge-diff
// schema that client-go generates for its apply configurations. That covers
// every built-in group-version client-go knows and is regenerated with each
// client-go release, so it cannot drift from the API types the rest of this
// binary is compiled against.
//
// This schema and the /openapi/v3 document an apiserver serves have the same
// origin: both are generated from the +listType / +listMapKey / +patchStrategy
// markers on the k8s.io/api Go types. That is why it is not an approximation --
// but it is a shared origin, not a checked equivalence, and nothing here
// compares the two documents. What is pinned instead is the behaviour that
// matters: the tests assert that a keyed list merges by key. The definitions the
// apiserver itself builds from live in k8s.io/kubernetes/pkg/generated/openapi,
// which is not importable, so this is the only importable source of them.
//
// Kinds the scheme does not recognize -- custom resources -- have no schema at
// all here and fall back to a deduced converter, which merges atomically. That
// is reported as a warning rather than left silent. Closing the gap properly
// means taking the schema from a CRD the user supplies, since nothing else can
// know a custom resource's shape; that needs an input for the CRD and so is
// left to its own change.
//
// Note that upstream drives this through patch.NewTypeConverterManager. That is
// not a path we can borrow: the apiserver passes it a nil static converter and
// resolves every type -- built-in and custom alike -- by fetching /openapi/v3
// from itself over the loopback client, with a goroutine polling to keep the
// path cache warm. The HTTP round-trip is what unifies the two schema sources;
// there is no in-process producer covering both. We resolve synchronously
// instead, so nothing polls in the browser.
var (
	typeConverterOnce sync.Once
	deducedConverter  managedfields.TypeConverter
	schemaConverter   managedfields.TypeConverter
	// permissiveParser accepts fields the schema does not declare; strictParser
	// is the same schema unmodified, used only to find out which fields those
	// are so they can be reported. See permissiveTypes.
	permissiveParser *typed.Parser
	strictParser     *typed.Parser
)

// deducedTypeName is the structured-merge-diff type that accepts any value and
// works out its structure at runtime. kube-openapi's schemaconv emits it into
// every schema it generates, so it is always present alongside the real types.
const deducedTypeName = "__untyped_deduced_"

func initTypeConverters() {
	deducedConverter = managedfields.NewDeducedTypeConverter()

	// client-go exposes its generated schema only from behind a TypeConverter,
	// so it is read back off a parsed value. Any registered kind will do;
	// ConfigMap is the cheapest.
	probe, err := applyconfigurations.NewTypeConverter(scheme.Scheme).ObjectToTyped(
		&corev1.ConfigMap{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}})
	if err != nil {
		// Leaves the parsers nil, so every lookup falls back to the deduced
		// converter. The schema is compiled into client-go, so this is not
		// reachable in practice.
		return
	}
	generated := probe.Schema()

	// Built rather than struct-copied: smdschema.Schema carries an unexported
	// lookup cache. Its Types slice holds values whose payloads are all
	// pointers, so sharing that between two parsers is safe.
	strictParser = &typed.Parser{Schema: smdschema.Schema{Types: generated.Types}}
	permissiveParser = &typed.Parser{Schema: smdschema.Schema{Types: permissiveTypes(generated)}}
	schemaConverter = managedfields.NewSchemeTypeConverter(scheme.Scheme, permissiveParser)
}

// typeConverterFor returns the merge-semantics provider for gvk, preferring the
// generated schema and falling back to a deduced converter. It never returns a
// nil converter. The second return reports whether a real schema was found.
//
// NewSchemeTypeConverter resolves a GVK to a definition name through the scheme
// and then looks that name up in the parser, so both steps have to succeed.
// Probing up front rather than reacting to a failure is deliberate: a merge
// parses two values -- the patch and the live object -- and rejects the pair
// unless both came from the same schema, so the choice between the generated
// and the deduced converter has to be made once, for the whole object.
func typeConverterFor(gvk schema.GroupVersionKind) (managedfields.TypeConverter, bool) {
	typeConverterOnce.Do(initTypeConverters)
	if permissiveParser == nil {
		return deducedConverter, false
	}
	name, err := scheme.Scheme.ToOpenAPIDefinitionName(gvk)
	if err != nil || !permissiveParser.Type(name).IsValid() {
		return deducedConverter, false
	}
	return schemaConverter, true
}

// rejectedValues returns the paths in object whose values the generated schema
// will not accept -- a string where an integer is declared, and the like --
// each with the reason, sorted, or nil when every value fits.
//
// A cluster catches this class for a JSONPatch by decoding the patched document
// into the typed object, strictly. The playground keeps everything
// unstructured, so upstream's patcher takes its unstructured branch and never
// makes that check; without this the object comes back with `replicas: "10"`
// and nothing says a cluster would have refused it.
//
// One parse, unlike undeclaredFields: a value the schema rejects is reported
// wherever it sits, so there is nothing to prune and repeat.
func rejectedValues(gvk schema.GroupVersionKind, object runtime.Object) []string {
	typeConverterOnce.Do(initTypeConverters)
	if strictParser == nil {
		return nil
	}
	name, err := scheme.Scheme.ToOpenAPIDefinitionName(gvk)
	if err != nil {
		return nil
	}
	parseable := strictParser.Type(name)
	if !parseable.IsValid() {
		return nil
	}
	content, err := runtime.DefaultUnstructuredConverter.ToUnstructured(object)
	if err != nil {
		return nil
	}
	_, err = parseable.FromUnstructured(content)
	if err == nil {
		return nil
	}
	var validation typed.ValidationErrors
	if !errors.As(err, &validation) {
		return nil
	}
	var rejected []string
	for _, item := range validation {
		// Undeclared fields are the other function's business, and are reported
		// on their own terms.
		if strings.Contains(item.ErrorMessage, "field not declared in schema") {
			continue
		}
		rejected = append(rejected, item.Path+": "+item.ErrorMessage)
	}
	sort.Strings(rejected)
	return slices.Compact(rejected)
}

// undeclaredFields returns the paths in object that the generated schema does
// not declare, sorted, or nil when every field is known. It reports rather than
// rejects; see permissiveTypes for why.
//
// The second return says the list may be incomplete: the probe below finds one
// field per map per parse and gives up after maxProbes, and which fields it
// reaches then depends on map iteration order. A caller that prints the list has
// to say so rather than presenting it as everything that is wrong.
func undeclaredFields(gvk schema.GroupVersionKind, object runtime.Object) ([]string, bool) {
	typeConverterOnce.Do(initTypeConverters)
	if strictParser == nil {
		return nil, false
	}
	name, err := scheme.Scheme.ToOpenAPIDefinitionName(gvk)
	if err != nil {
		return nil, false
	}
	parseable := strictParser.Type(name)
	if !parseable.IsValid() {
		return nil, false
	}
	content, err := runtime.DefaultUnstructuredConverter.ToUnstructured(object)
	if err != nil {
		return nil, false
	}

	// structured-merge-diff stops walking a map at its first undeclared field
	// (typed/validate.go returns false from the iteration callback), so one
	// parse reports at most one field per map. Each one found is pruned from a
	// copy and the parse repeated, which turns "the first problem" into the
	// whole list. maxProbes only bounds a pathological document; real objects
	// converge after a handful of rounds.
	const maxProbes = 32
	probe := content
	seen := map[string]struct{}{}
	truncated := true
	for range maxProbes {
		_, err := parseable.FromUnstructured(probe)
		if err == nil {
			truncated = false
			break
		}
		var validation typed.ValidationErrors
		if !errors.As(err, &validation) {
			break
		}
		found := false
		undeclaredRemain := false
		for _, item := range validation {
			// Only undeclared fields are collected. Any other validation
			// failure is a real error and the permissive parse surfaces it on
			// its own terms.
			if !strings.Contains(item.ErrorMessage, "field not declared in schema") {
				continue
			}
			undeclaredRemain = true
			if _, repeat := seen[item.Path]; repeat {
				continue
			}
			seen[item.Path] = struct{}{}
			if pruned, ok := pruneField(probe, item.Path); ok {
				probe = pruned
				found = true
			}
		}
		if !found {
			// Two different endings. If the parse still names an undeclared
			// field that could not be pruned -- a path through a list element,
			// or a field name containing a dot -- the search is stuck and more
			// may exist. If it names none, every undeclared field has been
			// found and the parse is only still failing for some unrelated
			// reason, so the list is complete.
			truncated = undeclaredRemain
			break
		}
	}

	if len(seen) == 0 {
		return nil, false
	}
	paths := make([]string, 0, len(seen))
	for path := range seen {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths, truncated
}

// pruneField removes the value at a dotted field path (".spec.foo") from a deep
// copy of content, reporting whether it did. Paths that descend through a list
// element are not dotted and are left alone; the caller stops probing then.
func pruneField(content map[string]any, path string) (map[string]any, bool) {
	if !strings.HasPrefix(path, ".") || strings.ContainsAny(path, "[]") {
		return nil, false
	}
	keys := strings.Split(strings.TrimPrefix(path, "."), ".")
	pruned := runtime.DeepCopyJSON(content)
	cursor := pruned
	for _, key := range keys[:len(keys)-1] {
		next, ok := cursor[key].(map[string]any)
		if !ok {
			return nil, false
		}
		cursor = next
	}
	leaf := keys[len(keys)-1]
	if _, ok := cursor[leaf]; !ok {
		return nil, false
	}
	delete(cursor, leaf)
	return pruned, true
}

// permissiveTypes returns generated's type definitions with every closed struct
// made to accept undeclared keys as deduced values. It is the equivalent of
// kube-openapi's preserveUnknownFields, which the generated schema has no knob
// for.
//
// The apiserver rejects a field its schema does not declare, because on a
// cluster the schema *is* the contract. The playground has no such authority:
// its schema is whatever client-go was vendored at build time, so a field from
// a newer Kubernetes would be reported to the user as their mistake. Accepting
// undeclared fields keeps those working while still using the schema for merge
// semantics. The cost -- that a genuine typo is carried through rather than
// rejected -- is paid back by undeclaredFields, which reports both cases as a
// warning rather than leaving them silent.
func permissiveTypes(generated *smdschema.Schema) []smdschema.TypeDef {
	types := make([]smdschema.TypeDef, 0, len(generated.Types))
	for i := range generated.Types {
		// Atom is three pointers, so copying it shares the payloads rather than
		// copying the locks inside them.
		def := smdschema.TypeDef{Name: generated.Types[i].Name, Atom: generated.Types[i].Atom}
		if opened, ok := openStruct(def.Map); ok {
			def.Map = opened
		}
		types = append(types, def)
	}
	return types
}

// openStruct returns a copy of m that accepts undeclared keys, and whether one
// was needed. A struct that already declares an ElementType is an
// additionalProperties map and has to keep the value type it declares.
func openStruct(m *smdschema.Map) (*smdschema.Map, bool) {
	if m == nil || len(m.Fields) == 0 || !isEmptyRef(m.ElementType) {
		return nil, false
	}
	// CopyInto rather than a struct copy: Map memoizes its field lookups behind
	// an unexported sync.Once, which must not be copied by value.
	opened := &smdschema.Map{}
	m.CopyInto(opened)
	deduced := deducedTypeName
	opened.ElementType = smdschema.TypeRef{NamedType: &deduced}
	return opened, true
}

func isEmptyRef(ref smdschema.TypeRef) bool {
	return ref.NamedType == nil &&
		ref.Inlined.Scalar == nil && ref.Inlined.List == nil && ref.Inlined.Map == nil
}

// andPossiblyMore is the clause a warning needs when undeclaredFields could not
// finish walking the object.
func andPossiblyMore(more bool) string {
	if !more {
		return ""
	}
	return ", and possibly others it could not reach"
}

// without returns the paths in fields that are not in exclude. Both are sorted
// and short -- a handful of entries at most -- so a linear scan is enough.
func without(fields, exclude []string) []string {
	if len(exclude) == 0 {
		return fields
	}
	kept := make([]string, 0, len(fields))
	for _, field := range fields {
		if !slices.Contains(exclude, field) {
			kept = append(kept, field)
		}
	}
	return kept
}
