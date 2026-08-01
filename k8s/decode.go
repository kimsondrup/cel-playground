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
	"fmt"
	"strings"

	apimachineryjson "k8s.io/apimachinery/pkg/util/json"
	kjson "sigs.k8s.io/json"
	sigsyaml "sigs.k8s.io/yaml"
)

// decodeTyped parses one YAML or JSON document into a Kubernetes API type the
// way the apiserver parses it: YAML converted to JSON, then unmarshalled
// case-sensitively with integral numbers preserved.
//
// The case sensitivity is the point. sigs.k8s.io/yaml.Unmarshal goes through
// encoding/json, which matches struct fields case-insensitively, so a policy
// that said `Validations:` would evaluate here and be ignored by a cluster.
//
// strict additionally rejects unknown fields and duplicate keys, which is what
// kubectl asks for: it sends fieldValidation=Strict, so a misspelled field is
// an error at apply time rather than a warning and a silent drop. Use it for
// every closed Kubernetes type the playground reads -- the policy, the RBAC
// tab, the request, the namespace -- because a field dropped there produces a
// wrong answer with no other symptom. The object and oldObject tabs stay
// lenient: they are arbitrary resources the playground has no schema for.
func decodeTyped(input []byte, into any, strict bool) error {
	if !strict {
		jsonBytes, err := sigsyaml.YAMLToJSON(input)
		if err != nil {
			return err
		}
		return kjson.UnmarshalCaseSensitivePreserveInts(jsonBytes, into)
	}
	// YAMLToJSONStrict is what rejects a duplicate key: YAML is parsed into a
	// map before it ever becomes JSON, so a repeated field would otherwise have
	// overwritten its earlier self long before the JSON decoder could object.
	jsonBytes, err := sigsyaml.YAMLToJSONStrict(input)
	if err != nil {
		return err
	}
	strictErrs, err := kjson.UnmarshalStrict(jsonBytes, into)
	if err != nil {
		return err
	}
	if len(strictErrs) > 0 {
		return fmt.Errorf("%w", errors.Join(strictErrs...))
	}
	return nil
}

// decodeObjectInput parses user-supplied resource YAML (the object/oldObject
// tabs) into the map[string]any the CEL activation binds, reproducing exactly
// what a real cluster does to the document before admission control ever sees
// it. kubectl converts YAML to JSON client-side with
// sigs.k8s.io/yaml.YAMLToJSON -- which is YAML 1.1, so bare `on`/`off`/`yes`/`no`
// keys and values coerce to booleans (and, because `on` and `yes` both become
// the key `true`, one such annotation is silently dropped, just as a cluster
// drops it). The apiserver then decodes that JSON with apimachinery's util/json,
// which keeps integral numbers as int64 rather than float64, so CEL sees them as
// `int` and integer arithmetic, `%` and `type(x) == int` behave as they do on a
// cluster. An empty or whitespace-only input yields a nil map, mirroring an
// empty editor tab in the playground UI.
//
// The vap and webhook modes share this decoder so that both modes show what a
// cluster would do with the same document.
func decodeObjectInput(input []byte) (map[string]any, error) {
	if len(strings.TrimSpace(string(input))) == 0 {
		return nil, nil
	}
	jsonBytes, err := sigsyaml.YAMLToJSON(input)
	if err != nil {
		return nil, err
	}
	var decoded map[string]any
	if err := apimachineryjson.Unmarshal(jsonBytes, &decoded); err != nil {
		// The document parsed as YAML and is simply not a mapping -- a bare
		// string, a list. encoding/json's "cannot unmarshal string into Go
		// value of type map[string]interface {}" names neither YAML nor
		// anything the reader typed.
		return nil, fmt.Errorf("expected a YAML mapping with apiVersion and kind")
	}
	return decoded, nil
}
