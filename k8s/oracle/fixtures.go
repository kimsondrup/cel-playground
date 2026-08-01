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

package oracle

import (
	"fmt"
	"os"
	"path/filepath"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	apimachineryjson "k8s.io/apimachinery/pkg/util/json"
	"sigs.k8s.io/yaml"
)

// RepoTestdata is the repository's existing k8s fixture tree, reached from this
// nested module. The oracle reads the very fixtures the unit tests assert on,
// so a divergence is a divergence on real inputs rather than on inputs invented
// for the oracle.
const RepoTestdata = "../testdata"

// VAPFixture returns the path of a fixture under k8s/testdata/vap. Note the
// literal spaces in the repo's fixture filenames.
func VAPFixture(name string) string { return filepath.Join(RepoTestdata, "vap", name) }

// WebhookFixture returns the path of a fixture under k8s/testdata/webhook.
func WebhookFixture(name string) string { return filepath.Join(RepoTestdata, "webhook", name) }

// LoadPolicy reads a ValidatingAdmissionPolicy from a YAML file.
//
// Whatever apiVersion the document declares, it is decoded into the v1 Go
// struct and the apiVersion rewritten to the one this apiserver serves (see
// TestAcceptanceServedVersions). The three versions are structurally identical
// for every field the playground exercises, and doing this is what lets one
// fixture drive both the in-process oracle and a real cluster.
func LoadPolicy(path string) (*admissionregistrationv1.ValidatingAdmissionPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var policy admissionregistrationv1.ValidatingAdmissionPolicy
	if err := yaml.UnmarshalStrict(data, &policy); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", path, err)
	}
	policy.APIVersion = admissionregistrationv1.SchemeGroupVersion.String()
	policy.Kind = "ValidatingAdmissionPolicy"
	return &policy, nil
}

// LoadUnstructured reads any YAML document into an unstructured object.
func LoadUnstructured(path string) (*unstructured.Unstructured, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	obj, err := decodeObject(data)
	if err != nil {
		return nil, fmt.Errorf("decoding %s: %w", path, err)
	}
	return obj, nil
}

// ParsePolicy decodes an inline policy YAML string.
func ParsePolicy(doc string) (*admissionregistrationv1.ValidatingAdmissionPolicy, error) {
	var policy admissionregistrationv1.ValidatingAdmissionPolicy
	if err := yaml.UnmarshalStrict([]byte(doc), &policy); err != nil {
		return nil, fmt.Errorf("decoding inline policy: %w", err)
	}
	policy.APIVersion = admissionregistrationv1.SchemeGroupVersion.String()
	policy.Kind = "ValidatingAdmissionPolicy"
	return &policy, nil
}

// ParseUnstructured decodes an inline object YAML string.
func ParseUnstructured(doc string) (*unstructured.Unstructured, error) {
	obj, err := decodeObject([]byte(doc))
	if err != nil {
		return nil, fmt.Errorf("decoding inline object: %w", err)
	}
	return obj, nil
}

// decodeObject reproduces what reaches admission on a cluster: kubectl turns
// YAML into JSON, the apiserver decodes that JSON keeping integral numbers as
// int64, and the object is stored unstructured. Going straight through
// sigs.k8s.io/yaml instead would leave every number a float64, and CEL would
// then have no overload for `%` or for comparing against an int -- an oracle
// artifact that looks exactly like a playground bug.
func decodeObject(data []byte) (*unstructured.Unstructured, error) {
	jsonBytes, err := yaml.YAMLToJSON(data)
	if err != nil {
		return nil, err
	}
	obj := &unstructured.Unstructured{}
	if err := apimachineryjson.Unmarshal(jsonBytes, &obj.Object); err != nil {
		return nil, err
	}
	return obj, nil
}
