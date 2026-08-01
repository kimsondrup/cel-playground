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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	celplugin "k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/cel/library"
)

// evalInputs is everything the CEL activation binds, in the shape apiserver's
// environment declares: `request` is a real admission.k8s.io/v1
// AdmissionRequest and `namespaceObject` a real core/v1 Namespace, both
// flattened with the unstructured converter the apiserver uses.
type evalInputs struct {
	object    map[string]any
	oldObject map[string]any
	request   map[string]any
	// namespaceObject is the namespace as CreateNamespaceObject exposes it: the
	// declared CEL type has exactly the fields that trim keeps, so nothing an
	// expression can name survives it.
	namespaceObject           map[string]any
	authorizer                any
	requestResourceAuthorizer any

	// The typed forms of the same tabs. Upstream's mutating patchers take these
	// rather than the flattened maps, and it is the same values either way, so
	// the two halves of a MutatingAdmissionPolicy cannot disagree about what
	// was in the editor.
	objectValue    *unstructured.Unstructured
	oldObjectValue *unstructured.Unstructured
	// namespace is untrimmed. The mutating dispatcher passes the Namespace as it
	// read it, where the validating validator passes it through
	// CreateNamespaceObject first.
	namespace *corev1.Namespace
	// attributes is what the Request tab stands for, and admissionRequest is
	// what the apiserver derives from it and binds as `request`.
	attributes       admission.Attributes
	admissionRequest *admissionv1.AdmissionRequest
	rbacAuthorizer   authorizer.Authorizer
}

// newEvalInputs decodes the playground's editor tabs.
//
// `request` is not the tab: it is what the apiserver builds out of the
// admission attributes with CreateAdmissionRequest, which is the only way any
// expression on a cluster ever sees it. The tab supplies the attributes, so
// everything it names is carried through, and the fields a cluster derives --
// requestKind, requestResource, dryRun and the operation's options -- are
// derived here too instead of reading as absent.
func newEvalInputs(oldObjectInput, objectInput, namespaceInput, requestInput, authorizerInput []byte) (*evalInputs, error) {
	oldObject, err := decodeObjectInput(oldObjectInput)
	if err != nil {
		return nil, fmt.Errorf("failed to decode input for the old resource value: %w", err)
	}
	object, err := decodeObjectInput(objectInput)
	if err != nil {
		return nil, fmt.Errorf("failed to decode input for the new resource value: %w", err)
	}
	namespace, err := decodeNamespaceInput(namespaceInput)
	if err != nil {
		return nil, fmt.Errorf("failed to decode input for the namespace: %w", err)
	}
	namespaceObject, err := objectToMap(celplugin.CreateNamespaceObject(namespace))
	if err != nil {
		return nil, fmt.Errorf("failed to convert the namespace for evaluation: %w", err)
	}
	request, err := decodeRequestInput(requestInput)
	if err != nil {
		return nil, fmt.Errorf("failed to decode input for the request: %w", err)
	}

	rbacAuthorizer, err := NewRBACAuthorizer(authorizerInput)
	if err != nil {
		return nil, err
	}
	userInfo := requestUserInfo(request)

	objectValue := unstructuredOrNil(object)
	oldObjectValue := unstructuredOrNil(oldObject)
	operation := admission.Operation(request.Operation)
	attributes := admission.NewAttributesRecord(
		runtimeObject(objectValue), runtimeObject(oldObjectValue),
		schema.GroupVersionKind(request.Kind),
		request.Namespace, request.Name,
		schema.GroupVersionResource(request.Resource),
		request.SubResource, operation, operationOptions(operation),
		request.DryRun != nil && *request.DryRun, userInfo,
	)
	admissionRequest := celplugin.CreateAdmissionRequest(attributes,
		metav1.GroupVersionResource(attributes.GetResource()),
		metav1.GroupVersionKind(attributes.GetKind()))
	requestMap, err := objectToMap(admissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to convert the request for evaluation: %w", err)
	}

	return &evalInputs{
		object:                    object,
		oldObject:                 oldObject,
		namespaceObject:           namespaceObject,
		request:                   requestMap,
		authorizer:                library.NewAuthorizerVal(userInfo, rbacAuthorizer),
		requestResourceAuthorizer: library.NewResourceAuthorizerVal(userInfo, rbacAuthorizer, attributes),
		objectValue:               objectValue,
		oldObjectValue:            oldObjectValue,
		namespace:                 namespace,
		attributes:                attributes,
		admissionRequest:          admissionRequest,
		rbacAuthorizer:            rbacAuthorizer,
	}, nil
}

// operationOptions is the options object a cluster attaches to the request for
// each operation. An operation the Request tab does not name gets none, rather
// than an invented CreateOptions.
func operationOptions(operation admission.Operation) runtime.Object {
	switch operation {
	case admission.Create:
		return &metav1.CreateOptions{}
	case admission.Update:
		return &metav1.UpdateOptions{}
	case admission.Delete:
		return &metav1.DeleteOptions{}
	default:
		return nil
	}
}

// unstructuredOrNil wraps a decoded tab, or returns nil for an empty one.
func unstructuredOrNil(content map[string]any) *unstructured.Unstructured {
	if len(content) == 0 {
		return nil
	}
	return &unstructured.Unstructured{Object: content}
}

// runtimeObject turns an absent object into an untyped nil. A nil
// *unstructured.Unstructured stored in a runtime.Object is not nil, and both
// the admission attributes and the CEL activation test the interface against
// nil to decide whether `object` binds as null.
func runtimeObject(value *unstructured.Unstructured) runtime.Object {
	if value == nil {
		return nil
	}
	return value
}

// decodeNamespaceInput parses the namespace tab as a real core/v1 Namespace.
func decodeNamespaceInput(input []byte) (*corev1.Namespace, error) {
	if len(strings.TrimSpace(string(input))) == 0 {
		return nil, nil
	}
	namespace := &corev1.Namespace{}
	if err := decodeTyped(input, namespace, true); err != nil {
		return nil, err
	}
	return namespace, nil
}

// decodeRequestInput parses the request tab as a real AdmissionRequest. The tab
// is written in the shape an expression reads, which is the shape a cluster
// hands to CEL; the attributes it stands for are rebuilt from it in
// newEvalInputs.
//
// It is read strictly. AdmissionRequest and Namespace are closed types, and a
// field the playground silently drops is a field the user believes they set:
// `Username:` for `username:` would leave the request anonymous and every
// authorizer check unanswered, with nothing on screen to say why.
func decodeRequestInput(input []byte) (*admissionv1.AdmissionRequest, error) {
	request := &admissionv1.AdmissionRequest{}
	if len(strings.TrimSpace(string(input))) == 0 {
		return request, nil
	}
	if err := decodeTyped(input, request, true); err != nil {
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
