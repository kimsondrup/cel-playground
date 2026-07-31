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

package k8s_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/undistro/cel-playground/k8s"
	"gopkg.in/yaml.v3"
)

// mutatingExamples mirrors the structure of mutating_examples.yaml, which
// `make update-data` turns into web/assets/examples/map.json. The keys match
// the mode id and the tab ids in web/assets/modes.json.
type mutatingExamples struct {
	Examples []struct {
		Name           string `yaml:"name"`
		Category       string `yaml:"category"`
		Policy         string `yaml:"map"`
		DataObject     string `yaml:"dataObject"`
		DataOldObject  string `yaml:"dataOldObject"`
		DataNamespace  string `yaml:"dataNamespace"`
		DataRequest    string `yaml:"dataRequest"`
		DataAuthorizer string `yaml:"dataAuthorizer"`
	} `yaml:"examples"`
}

// TestMutatingExamplesAreEvaluable runs every shipped example through the
// evaluator, so a broken example cannot reach the playground UI. It asserts the
// examples produce a real mutation rather than merely not crashing.
func TestMutatingExamplesAreEvaluable(t *testing.T) {
	content, err := os.ReadFile("../mutating_examples.yaml")
	if err != nil {
		t.Fatalf("failed to read mutating_examples.yaml: %v", err)
	}
	var examples mutatingExamples
	if err := yaml.Unmarshal(content, &examples); err != nil {
		t.Fatalf("failed to parse mutating_examples.yaml: %v", err)
	}
	if len(examples.Examples) < 5 {
		t.Fatalf("got %d examples, want at least 5", len(examples.Examples))
	}

	for _, example := range examples.Examples {
		t.Run(example.Name, func(t *testing.T) {
			if example.Policy == "" {
				t.Fatal(`example has no "map" key; the playground would not be able to load it`)
			}
			out, err := k8s.EvalMutatingAdmissionPolicy(
				[]byte(example.Policy),
				[]byte(example.DataOldObject),
				[]byte(example.DataObject),
				[]byte(example.DataNamespace),
				[]byte(example.DataRequest),
				[]byte(example.DataAuthorizer),
			)
			if err != nil {
				t.Fatalf("EvalMutatingAdmissionPolicy() error = %v", err)
			}

			var response k8s.EvalResponse
			if err := json.Unmarshal([]byte(out), &response); err != nil {
				t.Fatalf("failed to unmarshal response %q: %v", out, err)
			}

			if len(response.Warnings) != 0 {
				t.Errorf("example reports warnings, so it does not demonstrate the mode cleanly: %q", response.Warnings)
			}
			for _, matchCondition := range response.MatchConditions {
				if matchCondition.IsError {
					t.Errorf("matchCondition %v failed: %v", matchCondition.Name, derefStr(matchCondition.Error))
				}
			}
			for _, variable := range response.MutationVariables {
				if variable.IsError {
					t.Errorf("variable %q failed: %v", variable.Name, derefStr(variable.Error))
				}
			}
			if len(response.Mutations) == 0 {
				t.Fatal("example produced no mutations")
			}
			for i, mutation := range response.Mutations {
				if mutation.IsError {
					t.Errorf("mutation %d (%s) failed: %v", i, mutation.PatchType, derefStr(mutation.Error))
				}
			}
			if response.FinalObject == "" {
				t.Error("example produced no final object")
			}
			if response.Diff == "" {
				t.Error("example did not change the object; it would not demonstrate anything")
			}
		})
	}
}
