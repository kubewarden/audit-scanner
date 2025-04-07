package report

import (
	"context"
	"fmt"
	"log/slog"

	auditConstants "github.com/kubewarden/audit-scanner/internal/constants"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

// PolicyReportStore is a store for PolicyReport and ClusterPolicyReport.
type PolicyReportStore struct {
	// client is a controller-runtime client that knows about PolicyReport and ClusterPolicyReport CRDs
	client client.Client
}

// NewPolicyReportStore creates a new PolicyReportStore.
func NewPolicyReportStore(client client.Client) *PolicyReportStore {
	return &PolicyReportStore{
		client: client,
	}
}

// CreateOrPatchPolicyReport creates or patches a PolicyReport.
func (s *PolicyReportStore) CreateOrPatchPolicyReport(ctx context.Context, policyReport *wgpolicy.PolicyReport) error {
	oldPolicyReport := &wgpolicy.PolicyReport{ObjectMeta: metav1.ObjectMeta{
		Name:      policyReport.GetName(),
		Namespace: policyReport.GetNamespace(),
	}}

	operation, err := controllerutil.CreateOrPatch(ctx, s.client, oldPolicyReport, func() error {
		oldPolicyReport.ObjectMeta.Labels = policyReport.ObjectMeta.Labels
		oldPolicyReport.ObjectMeta.OwnerReferences = policyReport.ObjectMeta.OwnerReferences
		oldPolicyReport.Scope = policyReport.Scope
		oldPolicyReport.Summary = policyReport.Summary
		oldPolicyReport.Results = policyReport.Results

		return nil
	})
	if err != nil {
		return err
	}

	slog.Debug(fmt.Sprintf("PolicyReport %s", operation),
		slog.Group("dict",
			slog.String("report-name", policyReport.GetName()),
			slog.String("report-version", policyReport.GetResourceVersion()),
			slog.String("resource-name", policyReport.Scope.Name),
			slog.String("resource-namespace", policyReport.Scope.Namespace),
			slog.String("resource-version", policyReport.Scope.ResourceVersion)))

	return nil
}

func (s *PolicyReportStore) DeleteOldPolicyReports(ctx context.Context, scanRunID, namespace string) error {
	labelSelector, err := labels.Parse(fmt.Sprintf("%s!=%s,%s=%s", auditConstants.AuditScannerRunUIDLabel, scanRunID, labelAppManagedBy, labelApp))
	if err != nil {
		return err
	}
	slog.Debug("Deleting old PolicyReports", slog.String("labelSelector", labelSelector.String()))

	return s.client.DeleteAllOf(ctx, &wgpolicy.PolicyReport{}, &client.DeleteAllOfOptions{ListOptions: client.ListOptions{
		LabelSelector: labelSelector,
		Namespace:     namespace,
	}})
}

// CreateOrPatchClusterPolicyReport creates or patches a ClusterPolicyReport.
func (s *PolicyReportStore) CreateOrPatchClusterPolicyReport(ctx context.Context, clusterPolicyReport *wgpolicy.ClusterPolicyReport) error {
	oldClusterPolicyReport := &wgpolicy.ClusterPolicyReport{ObjectMeta: metav1.ObjectMeta{
		Name: clusterPolicyReport.GetName(),
	}}

	operation, err := controllerutil.CreateOrPatch(ctx, s.client, oldClusterPolicyReport, func() error {
		oldClusterPolicyReport.ObjectMeta.Labels = clusterPolicyReport.ObjectMeta.Labels
		oldClusterPolicyReport.ObjectMeta.OwnerReferences = clusterPolicyReport.ObjectMeta.OwnerReferences
		oldClusterPolicyReport.Scope = clusterPolicyReport.Scope
		oldClusterPolicyReport.Summary = clusterPolicyReport.Summary
		oldClusterPolicyReport.Results = clusterPolicyReport.Results

		return nil
	})
	if err != nil {
		return err
	}

	slog.Debug(fmt.Sprintf("ClusterPolicyReport %s", operation),
		slog.Group("dict",
			slog.String("report-name", clusterPolicyReport.GetName()),
			slog.String("report-version", clusterPolicyReport.GetResourceVersion()),
			slog.String("resource-name", clusterPolicyReport.Scope.Name),
			slog.String("resource-namespace", clusterPolicyReport.Scope.Namespace),
			slog.String("resource-version", clusterPolicyReport.Scope.ResourceVersion)))

	return nil
}

func (s *PolicyReportStore) DeleteOldClusterPolicyReports(ctx context.Context, scanRunID string) error {
	labelSelector, err := labels.Parse(fmt.Sprintf("%s!=%s,%s=%s", auditConstants.AuditScannerRunUIDLabel, scanRunID, labelAppManagedBy, labelApp))
	if err != nil {
		return err
	}
	slog.Debug("Deleting old ClusterPolicyReports", slog.String("labelSelector", labelSelector.String()))

	return s.client.DeleteAllOf(ctx, &wgpolicy.ClusterPolicyReport{}, &client.DeleteAllOfOptions{ListOptions: client.ListOptions{
		LabelSelector: labelSelector,
	}})
}
