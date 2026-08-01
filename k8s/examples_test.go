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

package k8s_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/undistro/cel-playground/k8s"
	"sigs.k8s.io/yaml"
)

// The examples are what someone sees before they type anything, so a broken one
// is the first thing they learn. This runs every shipped example through the
// evaluator and insists that nothing it evaluated reported an error and that
// nothing ran past a cost budget.
//
// It reads the YAML sources rather than the generated web/assets/examples/*.json,
// so an example that was edited without running `make update-data` is still
// covered.
func TestShippedExamplesEvaluate(t *testing.T) {
	tests := []struct {
		file string
		eval func(example map[string]string) (string, error)
	}{{
		file: "../validating_examples.yaml",
		eval: func(example map[string]string) (string, error) {
			return k8s.EvalValidatingAdmissionPolicy(
				[]byte(example["vap"]),
				[]byte(example["dataOldObject"]),
				[]byte(example["dataObject"]),
				[]byte(example["dataNamespace"]),
				[]byte(example["dataRequest"]),
				[]byte(example["dataAuthorizer"]),
			)
		},
	}, {
		file: "../mutating_examples.yaml",
		eval: func(example map[string]string) (string, error) {
			return k8s.EvalMutatingAdmissionPolicy(
				[]byte(example["map"]),
				[]byte(example["dataOldObject"]),
				[]byte(example["dataObject"]),
				[]byte(example["dataNamespace"]),
				[]byte(example["dataRequest"]),
				[]byte(example["dataAuthorizer"]),
			)
		},
	}, {
		file: "../webhooks_examples.yaml",
		eval: func(example map[string]string) (string, error) {
			return k8s.EvalWebhook(
				[]byte(example["webhooks"]),
				[]byte(example["dataOldObject"]),
				[]byte(example["dataObject"]),
				[]byte(example["dataRequest"]),
				[]byte(example["dataAuthorizer"]),
			)
		},
	}}

	for _, tt := range tests {
		data, err := os.ReadFile(tt.file)
		if err != nil {
			t.Fatalf("reading %s: %v", tt.file, err)
		}
		file := struct {
			Examples []map[string]string `json:"examples"`
		}{}
		if err := yaml.Unmarshal(data, &file); err != nil {
			t.Fatalf("decoding %s: %v", tt.file, err)
		}
		if len(file.Examples) == 0 {
			t.Fatalf("%s declares no examples", tt.file)
		}
		for _, example := range file.Examples {
			t.Run(tt.file+"/"+example["name"], func(t *testing.T) {
				out, err := tt.eval(example)
				if err != nil {
					t.Fatalf("evaluating the example: %v", err)
				}
				response := k8s.EvalResponse{}
				if err := json.Unmarshal([]byte(out), &response); err != nil {
					t.Fatalf("decoding the response: %v", err)
				}
				assertNoErrors(t, "matchConditions", response.MatchConditions)
				assertNoErrors(t, "validations", response.Validations)
				assertNoErrors(t, "messageExpressions", response.MessageExpressions)
				assertNoErrors(t, "auditAnnotations", response.AuditAnnotations)
				for _, webhook := range response.WebhookMatchConditions {
					assertNoErrors(t, "webhookMatchConditions", webhook)
				}
				assertNoVariableErrors(t, "validationVariables", response.ValidationVariables)
				assertNoVariableErrors(t, "messageExpressionVariables", response.MessageExpressionVariables)
				assertNoVariableErrors(t, "auditAnnotationVariables", response.AuditAnnotationVariables)
				assertNoVariableErrors(t, "mutationVariables", response.MutationVariables)
				for i, mutation := range response.Mutations {
					if mutation.IsError {
						t.Errorf("mutations[%d] failed: %s", i, *mutation.Error)
					}
				}
				// An example that shows a mutation has to produce one; one that
				// silently changed nothing teaches the wrong lesson.
				if len(response.Mutations) > 0 && response.FinalObject == "" {
					t.Errorf("the example's mutations left the object unchanged")
				}
				if len(response.Warnings) > 0 {
					t.Errorf("the example raises a warning: %s", response.Warnings[0])
				}
				if len(response.ExceededBudgets) > 0 {
					t.Errorf("the example runs past a cost budget: %v", *response.ExceededBudgets[0].Error)
				}
			})
		}
	}
}

func assertNoErrors(t *testing.T, section string, results []*k8s.EvalResult) {
	t.Helper()
	for i, result := range results {
		if result.IsError {
			t.Errorf("%s[%d] failed: %s", section, i, *result.Error)
		}
	}
}

func assertNoVariableErrors(t *testing.T, section string, variables []*k8s.EvalVariable) {
	t.Helper()
	for _, variable := range variables {
		if variable.IsError {
			t.Errorf("%s %q failed: %s", section, variable.Name, *variable.Error)
		}
	}
}
