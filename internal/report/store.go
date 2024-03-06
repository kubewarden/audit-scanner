package report

import (
	"context"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

// PolicyReportStore is a store for PolicyReport and ClusterPolicyReport
type PolicyReportStore struct {
	// client is a controller-runtime client that knows about PolicyReport and ClusterPolicyReport CRDs
	client client.Client
}

// NewPolicyReportStore creates a new PolicyReportStore
func NewPolicyReportStore(client client.Client) *PolicyReportStore {
	return &PolicyReportStore{
		client: client,
	}
}

// GetPolicyReport gets a PolicyReport by name and namespace
func (s *PolicyReportStore) GetPolicyReport(ctx context.Context, name, namespace string) (*wgpolicy.PolicyReport, error) {
	policyReport := &wgpolicy.PolicyReport{}
	err := s.client.Get(ctx, types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}, policyReport)
	if err != nil {
		return nil, err
	}

	return policyReport, nil
}

// CreateOrUpdatePolicyReport creates or updates a PolicyReport
func (s *PolicyReportStore) CreateOrUpdatePolicyReport(ctx context.Context, oldPolicyReport, policyReport *wgpolicy.PolicyReport) error {
	if oldPolicyReport != nil {
		oldPolicyReport.ObjectMeta.Labels = policyReport.ObjectMeta.Labels
		oldPolicyReport.ObjectMeta.OwnerReferences = policyReport.ObjectMeta.OwnerReferences
		oldPolicyReport.Scope = policyReport.Scope
		oldPolicyReport.Summary = policyReport.Summary
		oldPolicyReport.Results = policyReport.Results

		return s.client.Update(ctx, oldPolicyReport)
	}

	return s.client.Create(ctx, policyReport)
}

// GetPolicyReport gets a PolicyReport by name and namespace
func (s *PolicyReportStore) GetClusterPolicyReport(ctx context.Context, name string) (*wgpolicy.ClusterPolicyReport, error) {
	clusterPolicyReport := &wgpolicy.ClusterPolicyReport{}
	err := s.client.Get(ctx, types.NamespacedName{
		Name: name,
	}, clusterPolicyReport)
	if err != nil {
		return nil, err
	}

	return clusterPolicyReport, nil
}

// CreateOrUpdateClusterPolicyReport creates or updates a ClusterPolicyReport
func (s *PolicyReportStore) CreateOrUpdateClusterPolicyReport(ctx context.Context, oldClusterPolicyReport, clusterPolicyReport *wgpolicy.ClusterPolicyReport) error {
	if oldClusterPolicyReport != nil {
		oldClusterPolicyReport.ObjectMeta.Labels = clusterPolicyReport.ObjectMeta.Labels
		oldClusterPolicyReport.ObjectMeta.OwnerReferences = clusterPolicyReport.ObjectMeta.OwnerReferences
		oldClusterPolicyReport.Scope = clusterPolicyReport.Scope
		oldClusterPolicyReport.Summary = clusterPolicyReport.Summary
		oldClusterPolicyReport.Results = clusterPolicyReport.Results

		return s.client.Update(ctx, oldClusterPolicyReport)
	}

	return s.client.Create(ctx, clusterPolicyReport)
}
