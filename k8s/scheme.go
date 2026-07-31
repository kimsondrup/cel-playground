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
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	admissionregistrationv1alpha1 "k8s.io/api/admissionregistration/v1alpha1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/runtime/serializer/recognizer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

// policyScheme knows only the group-versions the playground can actually be
// handed: the three admissionregistration.k8s.io versions that carry
// ValidatingAdmissionPolicy, ValidatingWebhookConfiguration and
// MutatingWebhookConfiguration. Using k8s.io/client-go/kubernetes/scheme here
// would drag in every built-in Kubernetes API group instead.
var policyScheme = runtime.NewScheme()

// policyDeserializer recognises JSON and YAML only. serializer.NewCodecFactory
// would also build a protobuf serializer, which the playground can never use --
// dropping it keeps k8s.io/apimachinery/pkg/runtime/serializer/protobuf out of
// the binary. That is worth about 40 KB raw / 13 KB gzip on its own: it does
// *not* let the linker drop the generated gogo Marshal/Unmarshal methods on the
// API types, which are retained by scheme registration itself.
var policyDeserializer runtime.Decoder

func init() {
	utilruntime.Must(admissionregistrationv1.AddToScheme(policyScheme))
	utilruntime.Must(admissionregistrationv1beta1.AddToScheme(policyScheme))
	utilruntime.Must(admissionregistrationv1alpha1.AddToScheme(policyScheme))

	jsonSerializer := json.NewSerializerWithOptions(
		json.DefaultMetaFactory, policyScheme, policyScheme,
		json.SerializerOptions{Yaml: false, Pretty: false, Strict: false},
	)
	yamlSerializer := json.NewSerializerWithOptions(
		json.DefaultMetaFactory, policyScheme, policyScheme,
		json.SerializerOptions{Yaml: true, Pretty: false, Strict: false},
	)
	policyDeserializer = recognizer.NewDecoder(jsonSerializer, yamlSerializer)
}
