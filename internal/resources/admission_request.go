package resources

import (
	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func GenerateAdmissionRequest(resource unstructured.Unstructured) *admv1.AdmissionRequest {
	groupVersionKind := resource.GroupVersionKind()
	request := admv1.AdmissionRequest{
		UID:  resource.GetUID(),
		Name: resource.GetName(),
		Kind: metav1.GroupVersionKind{
			Group:   groupVersionKind.Group,
			Version: groupVersionKind.Version,
			Kind:    groupVersionKind.Kind,
		},
		Resource: metav1.GroupVersionResource{
			Group:    groupVersionKind.Group,
			Version:  groupVersionKind.Version,
			Resource: groupVersionKind.Kind,
		},
		Operation: admv1.Create,
		Namespace: resource.GetNamespace(),
		Object: runtime.RawExtension{
			Object: resource.DeepCopyObject(),
			Raw:    nil,
		},
	}
	return &request
}

func GenerateAdmissionReview(resource unstructured.Unstructured) *admv1.AdmissionReview {
	admissionRequest := GenerateAdmissionRequest(resource)
	return &admv1.AdmissionReview{
		Request:  admissionRequest,
		Response: nil,
	}
}
