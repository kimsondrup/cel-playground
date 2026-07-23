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
	"encoding/json"
	"sort"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"k8s.io/client-go/openapi"
	"k8s.io/client-go/openapi/openapitest"
	"k8s.io/kube-openapi/pkg/spec3"
)

// ApplyConfiguration mutations are applied with server-side-apply merge
// semantics, which need the OpenAPI schema of the target type: without it a
// list such as `spec.template.spec.initContainers` (x-kubernetes-list-type=map,
// keyed by name) would be *replaced* rather than merged by name, and the
// canonical sidecar-injection example would silently drop the existing
// containers.
//
// The playground has no cluster to discover schemas from, so it embeds the
// OpenAPI v3 specs that client-go ships for the built-in APIs. This is the
// same source kubernetes' own mutating-policy unit tests use. Group-versions
// with no embedded spec (CRDs, and any built-in group client-go does not
// embed) fall back to a deduced converter, which merges atomically.
//
// Note that upstream drives this through patch.NewTypeConverterManager, whose
// GetTypeConverter only resolves schemas after Run(ctx) has populated its path
// cache from a live /openapi/v3 endpoint. We deliberately do not use it: we
// read the embedded specs synchronously so no polling goroutine is started in
// the browser.
var (
	typeConverterOnce  sync.Once
	openapiPaths       map[string]openapi.GroupVersion
	deducedConverter   managedfields.TypeConverter
	typeConverterMu    sync.Mutex
	typeConverterCache map[schema.GroupVersion]typeConverterEntry
)

// typeConverterEntry pairs a converter with whether it came from a real OpenAPI
// schema. Callers need to know: without one, merges degrade to atomic lists
// silently, which is worth telling the user about.
type typeConverterEntry struct {
	converter    managedfields.TypeConverter
	schemaBacked bool
}

func initTypeConverters() {
	deducedConverter = managedfields.NewDeducedTypeConverter()
	typeConverterCache = map[schema.GroupVersion]typeConverterEntry{}
	paths, err := openapitest.NewEmbeddedFileClient().Paths()
	if err != nil {
		// Leaves openapiPaths nil, so every lookup falls back to the deduced
		// converter. The embedded client reads from an embed.FS, so this is
		// not reachable in practice.
		return
	}
	openapiPaths = paths
}

// typeConverterFor returns the merge-semantics provider for gvk, preferring the
// embedded OpenAPI schema for its group-version and falling back to a deduced
// converter. It never returns a nil converter. The second return reports whether
// a real schema was found.
func typeConverterFor(gvk schema.GroupVersionKind) (managedfields.TypeConverter, bool) {
	typeConverterOnce.Do(initTypeConverters)

	gv := gvk.GroupVersion()

	typeConverterMu.Lock()
	defer typeConverterMu.Unlock()

	if entry, ok := typeConverterCache[gv]; ok {
		return entry.converter, entry.schemaBacked
	}

	entry := typeConverterEntry{converter: deducedConverter}
	if path, ok := openapiPaths[openapiPathFor(gv)]; ok {
		if parsed, err := parseTypeConverter(path); err == nil {
			entry = typeConverterEntry{converter: parsed, schemaBacked: true}
		}
	}
	typeConverterCache[gv] = entry
	return entry.converter, entry.schemaBacked
}

// embeddedGroupVersions lists the group-versions the playground has a schema
// for, in the form a user writes in apiVersion, so a warning can say what IS
// covered. Derived from the embedded files rather than hard-coded, so it cannot
// drift when client-go is bumped.
func embeddedGroupVersions() []string {
	typeConverterOnce.Do(initTypeConverters)

	groupVersions := make([]string, 0, len(openapiPaths))
	for path := range openapiPaths {
		if trimmed, ok := strings.CutPrefix(path, "apis/"); ok {
			groupVersions = append(groupVersions, trimmed)
			continue
		}
		if trimmed, ok := strings.CutPrefix(path, "api/"); ok {
			groupVersions = append(groupVersions, trimmed)
		}
	}
	sort.Strings(groupVersions)
	return groupVersions
}

// openapiPathFor maps a group-version to the path key used by the OpenAPI v3
// discovery document: "api/v1" for core and "apis/<group>/<version>" otherwise.
func openapiPathFor(gv schema.GroupVersion) string {
	if gv.Group == "" {
		return "api/" + gv.Version
	}
	return "apis/" + gv.Group + "/" + gv.Version
}

func parseTypeConverter(entry openapi.GroupVersion) (managedfields.TypeConverter, error) {
	schemaBytes, err := entry.Schema(runtime.ContentTypeJSON)
	if err != nil {
		return nil, err
	}
	var openAPI spec3.OpenAPI
	if err := json.Unmarshal(schemaBytes, &openAPI); err != nil {
		return nil, err
	}
	// preserveUnknownFields is true where the apiserver passes false. The
	// embedded specs are frozen test fixtures and lag the API: Container has no
	// `restartPolicy`, so the canonical native-sidecar example would be
	// rejected with "field not declared in schema". Preserving unknown fields
	// keeps newer fields working while still using the schema for merge
	// semantics; the cost is that a misspelled field is carried through instead
	// of reported.
	return managedfields.NewTypeConverter(openAPI.Components.Schemas, true)
}
