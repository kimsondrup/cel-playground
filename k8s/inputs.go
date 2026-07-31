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
	"fmt"
	"reflect"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	celplugin "k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/cel/library"
	"sigs.k8s.io/yaml"
)

// evalInputs is everything the CEL activation binds, already in the shape
// apiserver's environment declares: `request` is a real
// admission.k8s.io/v1 AdmissionRequest and `namespaceObject` a real
// core/v1 Namespace, both flattened with the same unstructured converter the
// apiserver uses, instead of the hand-written mirror structs the playground
// used to carry (k8s/requestinfo.go, k8s/namespace.go).
type evalInputs struct {
	object                    map[string]any
	oldObject                 map[string]any
	request                   map[string]any
	namespaceObject           map[string]any
	authorizer                any
	requestResourceAuthorizer any
}

// newEvalInputs decodes the playground's editor tabs. namespaceInput may be nil
// for cluster-scoped requests; requestInput may be nil, in which case `request`
// is bound to an empty AdmissionRequest rather than left undeclared -- that is
// what a cluster does, and it means `request.name` reads as "" instead of
// failing to compile.
func newEvalInputs(oldObjectInput, objectInput, namespaceInput, requestInput, authorizerInput []byte) (*evalInputs, error) {
	oldObject, err := decodeObjectInput(oldObjectInput)
	if err != nil {
		return nil, fmt.Errorf("failed to decode input for the old resource value: %w", err)
	}
	object, err := decodeObjectInput(objectInput)
	if err != nil {
		return nil, fmt.Errorf("failed to decode input for the new resource value: %w", err)
	}
	namespaceObject, err := decodeNamespaceInput(namespaceInput)
	if err != nil {
		return nil, fmt.Errorf("failed to decode input for the namespace: %w", err)
	}
	request, err := decodeRequestInput(requestInput)
	if err != nil {
		return nil, fmt.Errorf("failed to decode input for the request: %w", err)
	}
	requestMap, err := objectToMap(request)
	if err != nil {
		return nil, fmt.Errorf("failed to convert the request for evaluation: %w", err)
	}

	authorizer, err := newPlaygroundAuthorizer(authorizerInput, request)
	if err != nil {
		return nil, err
	}
	userInfo := requestUserInfo(request)

	return &evalInputs{
		object:                    object,
		oldObject:                 oldObject,
		namespaceObject:           namespaceObject,
		request:                   requestMap,
		authorizer:                library.NewAuthorizerVal(userInfo, authorizer),
		requestResourceAuthorizer: library.NewResourceAuthorizerVal(userInfo, authorizer, requestResource{request: request}),
	}, nil
}

// decodeNamespaceInput parses the namespace tab as a real core/v1 Namespace and
// runs it through apiserver's own CreateNamespaceObject, which strips the
// fields (managedFields, ownerReferences, ...) a cluster does not expose to CEL.
func decodeNamespaceInput(input []byte) (map[string]any, error) {
	if len(strings.TrimSpace(string(input))) == 0 {
		return nil, nil
	}
	namespace := &corev1.Namespace{}
	if err := yaml.Unmarshal(input, namespace); err != nil {
		return nil, err
	}
	return objectToMap(celplugin.CreateNamespaceObject(namespace))
}

// decodeRequestInput parses the request tab as a real AdmissionRequest. The
// playground's request tab already *is* the admission request, so there is
// nothing for celplugin.CreateAdmissionRequest to derive -- that helper exists
// to build a request out of admission.Attributes, which the playground does not
// have.
func decodeRequestInput(input []byte) (*admissionv1.AdmissionRequest, error) {
	request := &admissionv1.AdmissionRequest{}
	if len(strings.TrimSpace(string(input))) == 0 {
		return request, nil
	}
	if err := yaml.Unmarshal(input, request); err != nil {
		return nil, err
	}
	return request, nil
}

func objectToMap(obj any) (map[string]any, error) {
	if obj == nil || reflect.ValueOf(obj).IsNil() {
		return nil, nil
	}
	return runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
}

func requestUserInfo(request *admissionv1.AdmissionRequest) user.Info {
	info := &user.DefaultInfo{
		Name:   request.UserInfo.Username,
		UID:    request.UserInfo.UID,
		Groups: request.UserInfo.Groups,
	}
	if len(request.UserInfo.Extra) > 0 {
		info.Extra = map[string][]string{}
		for key, value := range request.UserInfo.Extra {
			info.Extra[key] = value
		}
	}
	return info
}

// requestResource adapts the admission request to library.Resource, which is
// what apiserver uses to preconfigure `authorizer.requestResource`.
type requestResource struct {
	request *admissionv1.AdmissionRequest
}

func (r requestResource) GetName() string        { return r.request.Name }
func (r requestResource) GetNamespace() string   { return r.request.Namespace }
func (r requestResource) GetSubresource() string { return r.request.SubResource }

func (r requestResource) GetResource() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    r.request.Resource.Group,
		Version:  r.request.Resource.Version,
		Resource: r.request.Resource.Resource,
	}
}
