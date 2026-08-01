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

package k8s

import (
	_ "embed"
	"fmt"
	"sync"

	yamlv2 "go.yaml.in/yaml/v2"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"sigs.k8s.io/structured-merge-diff/v6/typed"
)

// An ApplyConfiguration mutation is applied with server-side-apply merge
// semantics, which need the schema of the target type. Without one, a list such
// as spec.template.spec.initContainers -- x-kubernetes-list-type=map, keyed by
// name -- is replaced rather than merged by name, so a sidecar-injection policy
// drops the containers that were already there and says nothing.
//
// A cluster always has a schema: the apiserver serves one per group-version
// from /openapi/v3, and upstream's patch.NewTypeConverterManager fetches it
// over an HTTP client. A browser has nowhere to point that client, and the only
// in-process producer of the same schema is client-go's generated
// apply-configuration parser, which costs +3.35 MB gzip to import -- fourteen
// times the rest of this mode.
//
// So the schema travels as data. builtinschema.yaml is client-go's own
// generated schema, verbatim, and builtingvks.yaml maps each kind onto its name
// in it. Both are produced and held to account by k8s/oracle's
// TestBuiltinSchemaIsCurrent, where importing client-go is free.
//
// Kinds outside that index -- custom resources -- have no schema here and fall
// back to a deduced converter, which merges every list atomically. That is what
// a cluster does for a CRD whose schema it cannot resolve, and it is reported
// rather than left silent.

//go:embed builtinschema.yaml
var builtinSchemaYAML string

//go:embed builtingvks.yaml
var builtinGVKsYAML string

var builtins struct {
	once   sync.Once
	parser *typed.Parser
	// names maps "<apiVersion>/<kind>" onto a type name in parser.
	names map[string]string
	err   error
}

func loadBuiltins() {
	builtins.once.Do(func() {
		parser, err := typed.NewParser(typed.YAMLObject(builtinSchemaYAML))
		if err != nil {
			builtins.err = fmt.Errorf("failed to parse the built-in merge schema: %w", err)
			return
		}
		names := map[string]string{}
		if err := yamlv2.Unmarshal([]byte(builtinGVKsYAML), &names); err != nil {
			builtins.err = fmt.Errorf("failed to parse the built-in kind index: %w", err)
			return
		}
		builtins.parser, builtins.names = parser, names
	})
}

// typeConverterFor returns the merge-semantics provider for gvk. The second
// return reports whether a real schema was found; when it is false the deduced
// converter is returned, which never fails and never merges by key.
func typeConverterFor(gvk schema.GroupVersionKind) (managedfields.TypeConverter, bool) {
	loadBuiltins()
	if builtins.err != nil || builtins.parser == nil {
		return managedfields.NewDeducedTypeConverter(), false
	}
	if _, ok := builtinTypeName(gvk); !ok {
		return managedfields.NewDeducedTypeConverter(), false
	}
	return builtinTypeConverter{}, true
}

func builtinTypeName(gvk schema.GroupVersionKind) (string, bool) {
	name, ok := builtins.names[gvk.GroupVersion().String()+"/"+gvk.Kind]
	return name, ok
}

// builtinTypeConverter is managedfields.NewSchemeTypeConverter without the
// scheme: it resolves a kind to a definition name through the generated index
// rather than through a runtime.Scheme, which would mean registering every
// built-in Go type in the binary to learn names that are already known.
type builtinTypeConverter struct{}

var _ managedfields.TypeConverter = builtinTypeConverter{}

func (builtinTypeConverter) ObjectToTyped(obj runtime.Object, opts ...typed.ValidationOptions) (*typed.TypedValue, error) {
	gvk := obj.GetObjectKind().GroupVersionKind()
	name, ok := builtinTypeName(gvk)
	if !ok {
		return nil, fmt.Errorf("no schema for %s", gvk)
	}
	parseable := builtins.parser.Type(name)
	if unstructuredObj, ok := obj.(*unstructured.Unstructured); ok {
		return parseable.FromUnstructured(unstructuredObj.UnstructuredContent(), opts...)
	}
	return parseable.FromStructured(obj, opts...)
}

func (builtinTypeConverter) TypedToObject(value *typed.TypedValue) (runtime.Object, error) {
	content, ok := value.AsValue().Unstructured().(map[string]any)
	if !ok {
		return nil, fmt.Errorf("the merged value is not an object")
	}
	return &unstructured.Unstructured{Object: content}, nil
}
