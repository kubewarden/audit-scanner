package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kubewarden/audit-scanner/internal/k8s"
	"github.com/kubewarden/audit-scanner/internal/policies"
	"github.com/kubewarden/audit-scanner/internal/report"
	"github.com/kubewarden/audit-scanner/internal/testutils"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	dynamicFake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
)

var (
	policyServer = &policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}

	policyServerService = &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"app": "kubewarden-policy-server-default",
			},
			Name:      "policy-server-default",
			Namespace: "kubewarden",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name: "http",
					Port: 443,
				},
			},
		},
	}
)

func newMockPolicyServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)

		admissionReview := admissionv1.AdmissionReview{
			Response: &admissionv1.AdmissionResponse{
				Allowed: true,
				Result:  nil,
			},
		}
		response, err := json.Marshal(admissionReview)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
		}

		_, err = writer.Write(response)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
		}
	}))
}

func TestScanAllNamespaces(t *testing.T) {
	mockPolicyServer := newMockPolicyServer()
	defer mockPolicyServer.Close()

	namespace1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace1",
		},
	}

	namespace2 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace2",
		},
	}

	pod1 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod1",
			Namespace: "namespace1",
			UID:       "pod1-uid",
		},
	}

	pod2 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod2",
			Namespace: "namespace2",
			UID:       "pod2-uid",
		},
	}

	deployment1 := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deployment1",
			Namespace: "namespace1",
			UID:       "deployment1-uid",
			Labels: map[string]string{
				"env": "test",
			},
		},
	}

	deployment2 := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deployment2",
			Namespace: "namespace2",
			UID:       "deployment2-uid",
			Labels: map[string]string{
				"env": "test",
			},
		},
	}

	// an AdmissionPolicy targeting pods in namespace1
	admissionPolicy1 := testutils.
		NewAdmissionPolicyFactory().
		Name("policy1").
		Namespace("namespace1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicy targeting deployments in namespace2
	admissionPolicy2 := testutils.
		NewAdmissionPolicyFactory().
		Name("policy2").
		Namespace("namespace2").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicy with an object selector that matches deployment1 in namespace1
	admissionPolicy3 := testutils.
		NewAdmissionPolicyFactory().
		Name("policy3").
		Namespace("namespace1").
		ObjectSelector(&metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "test"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicy with an object selector that does not match any deployment in namespace2
	admissionPolicy4 := testutils.
		NewAdmissionPolicyFactory().
		Name("policy4").
		Namespace("namespace2").
		ObjectSelector(&metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "prod"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicy targeting pods and deployments in all namespaces
	clusterAdmissionPolicy := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("policy5").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deployments"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	dynamicClient := dynamicFake.NewSimpleDynamicClient(
		scheme.Scheme,
		deployment1,
		deployment2,
		pod1,
		pod2)
	clientset := fake.NewSimpleClientset(
		namespace1,
		namespace2,
	)
	client := testutils.NewFakeClient(
		namespace1,
		namespace2,
		policyServer,
		policyServerService,
		admissionPolicy1,
		admissionPolicy2,
		admissionPolicy3,
		admissionPolicy4,
		clusterAdmissionPolicy,
	)

	k8sClient, err := k8s.NewClient(dynamicClient, clientset, "kubewarden", nil)
	require.NoError(t, err)

	policiesClient, err := policies.NewClient(client, "kubewarden", mockPolicyServer.URL)
	require.NoError(t, err)

	policyReportStore := report.NewPolicyReportStore(client)

	scanner, err := NewScanner(policiesClient, k8sClient, policyReportStore, false, false, true, "")
	require.NoError(t, err)
	err = scanner.ScanAllNamespaces(context.Background())
	require.NoError(t, err)

	policyReport, err := policyReportStore.GetPolicyReport(context.TODO(), string(pod1.GetUID()), "namespace1")
	require.NoError(t, err)
	assert.Equal(t, 2, policyReport.Summary.Pass)
	assert.Len(t, policyReport.Results, 2)

	policyReport, err = policyReportStore.GetPolicyReport(context.TODO(), string(pod2.GetUID()), "namespace2")
	require.NoError(t, err)
	assert.Equal(t, 1, policyReport.Summary.Pass)
	assert.Len(t, policyReport.Results, 1)

	policyReport, err = policyReportStore.GetPolicyReport(context.TODO(), string(deployment1.GetUID()), "namespace1")
	require.NoError(t, err)
	assert.Equal(t, 2, policyReport.Summary.Pass)
	assert.Len(t, policyReport.Results, 2)

	policyReport, err = policyReportStore.GetPolicyReport(context.TODO(), string(deployment2.GetUID()), "namespace2")
	require.NoError(t, err)
	assert.Equal(t, 2, policyReport.Summary.Pass)
	assert.Len(t, policyReport.Results, 2)
}

func TestScanClusterWideResources(t *testing.T) {
	mockPolicyServer := newMockPolicyServer()
	defer mockPolicyServer.Close()

	namespace1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace1",
			UID:  "namespace1-uid",
		},
	}

	namespace2 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace2",
			UID:  "namespace2-uid",
			Labels: map[string]string{
				"env": "test",
			},
		},
	}

	// a ClusterAdmissionPolicy targeting namespaces
	clusterAdmissionPolicy1 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("policy1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"namespaces"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicy targeting namespaces with an object selector that matches namespace2
	clusterAdmissionPolicy2 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("policy2").
		ObjectSelector(&metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "test"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"namespaces"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicy targeting namespaces with an object selector that does not match any namespace
	clusterAdmissionPolicy3 := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("policy3").
		ObjectSelector(&metav1.LabelSelector{
			MatchLabels: map[string]string{"env": "prod"},
		}).
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"namespaces"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	dynamicClient := dynamicFake.NewSimpleDynamicClient(
		scheme.Scheme,
		namespace1,
		namespace2,
	)
	clientset := fake.NewSimpleClientset(
		namespace1,
		namespace2,
	)
	client := testutils.NewFakeClient(
		namespace1,
		namespace2,
		policyServer,
		policyServerService,
		clusterAdmissionPolicy1,
		clusterAdmissionPolicy2,
		clusterAdmissionPolicy3,
	)

	k8sClient, err := k8s.NewClient(dynamicClient, clientset, "kubewarden", nil)
	require.NoError(t, err)

	policiesClient, err := policies.NewClient(client, "kubewarden", mockPolicyServer.URL)
	require.NoError(t, err)

	policyReportStore := report.NewPolicyReportStore(client)

	scanner, err := NewScanner(policiesClient, k8sClient, policyReportStore, false, false, true, "")
	require.NoError(t, err)
	err = scanner.ScanClusterWideResources(context.Background())
	require.NoError(t, err)

	clusterPolicyReport, err := policyReportStore.GetClusterPolicyReport(context.TODO(), string(namespace1.GetUID()))
	require.NoError(t, err)
	assert.Equal(t, 1, clusterPolicyReport.Summary.Pass)
	assert.Len(t, clusterPolicyReport.Results, 1)

	clusterPolicyReport, err = policyReportStore.GetClusterPolicyReport(context.TODO(), string(namespace2.GetUID()))
	require.NoError(t, err)
	assert.Equal(t, 2, clusterPolicyReport.Summary.Pass)
	assert.Len(t, clusterPolicyReport.Results, 2)
}

func TestAuditResourceExistingResult(t *testing.T) {
	resource := unstructured.Unstructured{}
	resource.SetName("pod")
	resource.SetNamespace("namespace")
	resource.SetUID("pod-uid")
	resource.SetResourceVersion("123")

	policy := &policies.Policy{
		Policy: &policiesv1.AdmissionPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "policy",
				Namespace:       "namespace",
				UID:             "policy-uid",
				ResourceVersion: "123",
			},
		},
	}
	admissionReview := &admissionv1.AdmissionReview{
		Response: &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Message: "the policy was rejected",
			},
		},
	}
	timestamp := metav1.Timestamp{Seconds: 1234567890}

	existingPolicyReport := report.NewPolicyReport(resource)
	existingResult := report.NewPolicyReportResult(policy, admissionReview, false, timestamp)
	report.AddResultToPolicyReport(existingPolicyReport, existingResult)

	dynamicClient := dynamicFake.NewSimpleDynamicClient(scheme.Scheme)
	clientset := fake.NewSimpleClientset()
	client := testutils.NewFakeClient(
		existingPolicyReport,
	)

	k8sClient, err := k8s.NewClient(dynamicClient, clientset, "kubewarden", nil)
	require.NoError(t, err)

	policiesClient, err := policies.NewClient(client, "kubewarden", "")
	require.NoError(t, err)

	policyReportStore := report.NewPolicyReportStore(client)

	scanner, err := NewScanner(policiesClient, k8sClient, policyReportStore, false, false, true, "")
	require.NoError(t, err)

	scanner.auditResource(context.TODO(), []*policies.Policy{policy}, resource)

	policyReport, err := policyReportStore.GetPolicyReport(context.TODO(), string(resource.GetUID()), resource.GetNamespace())
	require.NoError(t, err)

	assert.Len(t, policyReport.Results, 1)
	assert.Equal(t, existingResult, policyReport.Results[0])
}

func TestAuditClusterResourceExistingResult(t *testing.T) {
	resource := unstructured.Unstructured{}
	resource.SetName("namespace")
	resource.SetUID("namespace-uid")
	resource.SetResourceVersion("123")

	policy := &policies.Policy{
		Policy: &policiesv1.ClusterAdmissionPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "policy",
				UID:             "policy-uid",
				ResourceVersion: "123",
			},
		},
	}
	admissionReview := &admissionv1.AdmissionReview{
		Response: &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Message: "the policy was rejected",
			},
		},
	}
	timestamp := metav1.Timestamp{Seconds: 1234567890}

	existingClusterPolicyReport := report.NewClusterPolicyReport(resource)
	existingResult := report.NewPolicyReportResult(policy, admissionReview, false, timestamp)
	report.AddResultToClusterPolicyReport(existingClusterPolicyReport, existingResult)

	dynamicClient := dynamicFake.NewSimpleDynamicClient(scheme.Scheme)
	clientset := fake.NewSimpleClientset()
	client := testutils.NewFakeClient(
		existingClusterPolicyReport,
	)

	k8sClient, err := k8s.NewClient(dynamicClient, clientset, "kubewarden", nil)
	require.NoError(t, err)

	policiesClient, err := policies.NewClient(client, "kubewarden", "")
	require.NoError(t, err)

	policyReportStore := report.NewPolicyReportStore(client)

	scanner, err := NewScanner(policiesClient, k8sClient, policyReportStore, false, false, true, "")
	require.NoError(t, err)

	scanner.auditClusterResource(context.TODO(), []*policies.Policy{policy}, resource)

	clusterPolicyReport, err := policyReportStore.GetClusterPolicyReport(context.TODO(), string(resource.GetUID()))
	require.NoError(t, err)

	assert.Len(t, clusterPolicyReport.Results, 1)
	assert.Equal(t, existingResult, clusterPolicyReport.Results[0])
}
