package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	auditConstants "github.com/kubewarden/audit-scanner/internal/constants"
	"github.com/kubewarden/audit-scanner/internal/k8s"
	"github.com/kubewarden/audit-scanner/internal/policies"
	"github.com/kubewarden/audit-scanner/internal/report"
	auditscheme "github.com/kubewarden/audit-scanner/internal/scheme"
	"github.com/kubewarden/audit-scanner/internal/testutils"
	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apimachineryErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	dynamicFake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

const (
	parallelNamespacesAudits = 1
	parallelResourcesAudits  = 10
	parallelPoliciesAudits   = 2
	pageSize                 = 100
)

func newMockPolicyServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
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

	policyServer := &policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}

	policyServerService := &corev1.Service{
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

	// an AdmissionPolicy targeting an unknown GVR, should be counted as error
	admissionPolicyUnknownGVR := testutils.
		NewAdmissionPolicyFactory().
		Name("policy6").
		Namespace("namespace1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// an AdmissionPolicy targeting a GVR with *, should be skipped
	admissionPolicyAsteriskGVR := testutils.
		NewAdmissionPolicyFactory().
		Name("policy7").
		Namespace("namespace1").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"*"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// add a policy report that should be deleted by the scanner
	oldPolicyReportRunUID := uuid.New().String()
	oldPolicyReport := testutils.NewPolicyReportFactory().
		Name("report1").
		Namespace(namespace1.GetName()).
		WithAppLabel().
		RunUID(oldPolicyReportRunUID).
		Build()

	auditScheme, err := auditscheme.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	dynamicClient := dynamicFake.NewSimpleDynamicClient(
		auditScheme,
		deployment1,
		deployment2,
		pod1,
		pod2,
		namespace1,
		oldPolicyReport)
	clientset := fake.NewSimpleClientset(
		namespace1,
		namespace2,
	)
	client, err := testutils.NewFakeClient(
		namespace1,
		namespace2,
		policyServer,
		policyServerService,
		admissionPolicy1,
		admissionPolicy2,
		admissionPolicy3,
		admissionPolicy4,
		admissionPolicyUnknownGVR,
		admissionPolicyAsteriskGVR,
		clusterAdmissionPolicy,
		oldPolicyReport,
	)
	require.NoError(t, err)

	k8sClient, err := k8s.NewClient(dynamicClient, clientset, "kubewarden", nil, pageSize)
	require.NoError(t, err)

	policiesClient, err := policies.NewClient(client, "kubewarden", mockPolicyServer.URL)
	require.NoError(t, err)

	policyReportStore := report.NewPolicyReportStore(client)

	scanner, err := NewScanner(policiesClient, k8sClient, policyReportStore, false, false, true, "", parallelNamespacesAudits, parallelResourcesAudits, parallelPoliciesAudits)
	require.NoError(t, err)

	runUID := uuid.New().String()
	err = scanner.ScanAllNamespaces(context.Background(), runUID)
	require.NoError(t, err)

	policyReport := wgpolicy.PolicyReport{}

	err = client.Get(context.TODO(), types.NamespacedName{Name: oldPolicyReport.GetName(), Namespace: oldPolicyReport.GetNamespace()}, oldPolicyReport)
	require.True(t, apimachineryErrors.IsNotFound(err))

	err = client.Get(context.TODO(), types.NamespacedName{Name: string(pod1.GetUID()), Namespace: "namespace1"}, &policyReport)
	require.NoError(t, err)
	assert.Equal(t, 2, policyReport.Summary.Pass)
	assert.Equal(t, 1, policyReport.Summary.Error)
	assert.Equal(t, 1, policyReport.Summary.Skip)
	assert.Len(t, policyReport.Results, 2)
	assert.Equal(t, runUID, policyReport.GetLabels()[auditConstants.AuditScannerRunUIDLabel])

	err = client.Get(context.TODO(), types.NamespacedName{Name: string(pod2.GetUID()), Namespace: "namespace2"}, &policyReport)
	require.NoError(t, err)
	assert.Equal(t, 1, policyReport.Summary.Pass)
	assert.Len(t, policyReport.Results, 1)
	assert.Equal(t, runUID, policyReport.GetLabels()[auditConstants.AuditScannerRunUIDLabel])

	err = client.Get(context.TODO(), types.NamespacedName{Name: string(deployment1.GetUID()), Namespace: "namespace1"}, &policyReport)
	require.NoError(t, err)
	assert.Equal(t, 2, policyReport.Summary.Pass)
	assert.Equal(t, 1, policyReport.Summary.Error)
	assert.Equal(t, 1, policyReport.Summary.Skip)
	assert.Len(t, policyReport.Results, 2)
	assert.Equal(t, runUID, policyReport.GetLabels()[auditConstants.AuditScannerRunUIDLabel])

	err = client.Get(context.TODO(), types.NamespacedName{Name: string(deployment2.GetUID()), Namespace: "namespace2"}, &policyReport)
	require.NoError(t, err)
	assert.Equal(t, 2, policyReport.Summary.Pass)
	assert.Len(t, policyReport.Results, 2)
	assert.Equal(t, runUID, policyReport.GetLabels()[auditConstants.AuditScannerRunUIDLabel])
}

func TestScanClusterWideResources(t *testing.T) {
	mockPolicyServer := newMockPolicyServer()
	defer mockPolicyServer.Close()

	policyServer := &policiesv1.PolicyServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}

	policyServerService := &corev1.Service{
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

	// a ClusterAdmissionPolicy targeting an unknown GVR, should be counted as error
	clusterAdmissionPolicyUnknownGVR := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("policy4").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"foo"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// a ClusterAdmissionPolicy targeting a GVR with *, should be counted as skipped
	clusterAdmissionPolicyAsteriskGVR := testutils.
		NewClusterAdmissionPolicyFactory().
		Name("policy5").
		Rule(admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"*"},
		}).
		Status(policiesv1.PolicyStatusActive).
		Build()

	// add a policy report that should be deleted by the scanner
	oldClusterPolicyReportRunUID := uuid.New().String()
	oldClusterPolicyReport := testutils.NewClusterPolicyReportFactory().
		Name("report1").
		WithAppLabel().
		RunUID(oldClusterPolicyReportRunUID).
		Build()

	dynamicClient := dynamicFake.NewSimpleDynamicClient(
		scheme.Scheme,
		namespace1,
		namespace2,
		oldClusterPolicyReport,
	)
	clientset := fake.NewSimpleClientset(
		namespace1,
		namespace2,
	)
	client, err := testutils.NewFakeClient(
		namespace1,
		namespace2,
		policyServer,
		policyServerService,
		clusterAdmissionPolicy1,
		clusterAdmissionPolicy2,
		clusterAdmissionPolicy3,
		clusterAdmissionPolicyUnknownGVR,
		clusterAdmissionPolicyAsteriskGVR,
		oldClusterPolicyReport,
	)
	require.NoError(t, err)

	k8sClient, err := k8s.NewClient(dynamicClient, clientset, "kubewarden", nil, pageSize)
	require.NoError(t, err)

	policiesClient, err := policies.NewClient(client, "kubewarden", mockPolicyServer.URL)
	require.NoError(t, err)

	policyReportStore := report.NewPolicyReportStore(client)

	scanner, err := NewScanner(policiesClient, k8sClient, policyReportStore, false, false, true, "", parallelNamespacesAudits, parallelNamespacesAudits, parallelPoliciesAudits)
	require.NoError(t, err)

	runUID := uuid.New().String()
	err = scanner.ScanClusterWideResources(context.Background(), runUID)
	require.NoError(t, err)

	err = client.Get(context.TODO(), types.NamespacedName{Name: oldClusterPolicyReport.GetName()}, oldClusterPolicyReport)
	require.True(t, apimachineryErrors.IsNotFound(err))

	clusterPolicyReport := wgpolicy.ClusterPolicyReport{}

	err = client.Get(context.TODO(), types.NamespacedName{Name: string(namespace1.GetUID())}, &clusterPolicyReport)
	require.NoError(t, err)
	assert.Equal(t, 1, clusterPolicyReport.Summary.Pass)
	assert.Equal(t, 1, clusterPolicyReport.Summary.Error)
	assert.Equal(t, 1, clusterPolicyReport.Summary.Skip)
	assert.Len(t, clusterPolicyReport.Results, 1)
	assert.Equal(t, runUID, clusterPolicyReport.GetLabels()[auditConstants.AuditScannerRunUIDLabel])

	err = client.Get(context.TODO(), types.NamespacedName{Name: string(namespace2.GetUID())}, &clusterPolicyReport)
	require.NoError(t, err)
	assert.Equal(t, 2, clusterPolicyReport.Summary.Pass)
	assert.Len(t, clusterPolicyReport.Results, 2)
	assert.Equal(t, runUID, clusterPolicyReport.GetLabels()[auditConstants.AuditScannerRunUIDLabel])
}
