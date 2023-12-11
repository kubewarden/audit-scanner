package report_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kubewarden/audit-scanner/internal/report"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

func TestAddMemoryPolicyReportStore(t *testing.T) {
	t.Run("Add then Get namespaced PolicyReport", func(t *testing.T) {
		store, err := report.NewMemoryPolicyReportStore()
		require.NoError(t, err)

		_, err = store.GetPolicyReport(npr.GetNamespace())
		require.Error(t, err, "Should not be found in empty Store")

		err = store.SavePolicyReport(&npr)
		require.NoError(t, err, "Cannot save report: %v", err)

		_, err = store.GetPolicyReport(npr.GetNamespace())
		require.NoError(t, err, "Should be found in Store after adding report to the store: %v.", err)
	})

	t.Run("Clusterwide Add then Get", func(t *testing.T) {
		store, err := report.NewMemoryPolicyReportStore()
		require.NoError(t, err)

		err = store.SaveClusterPolicyReport(&cpr)
		require.NoError(t, err)

		_, err = store.GetClusterPolicyReport(cpr.ObjectMeta.Name)
		require.NoError(t, err, "Should be found in Store after adding report to the store")
	})
}

func TestDeleteMemoryPolicyReportStore(t *testing.T) {
	t.Run("Delete then Get namespaced PolicyReport", func(t *testing.T) {
		store, err := report.NewMemoryPolicyReportStore()
		require.NoError(t, err)

		err = store.SavePolicyReport(&npr)
		require.NoError(t, err, "Cannot save PolicyReport: %v", err)

		_, err = store.GetPolicyReport(npr.GetNamespace())
		require.NoError(t, err, "Should be found in Store after adding report to the store")

		_ = store.RemovePolicyReport(npr.GetNamespace())
		_, err = store.GetPolicyReport(npr.GetNamespace())
		require.Error(t, err, "Should not be found after Remove report from Store")
	})

	t.Run("Remove all namespaced", func(t *testing.T) {
		store, err := report.NewMemoryPolicyReportStore()
		require.NoError(t, err)

		_ = store.SavePolicyReport(&npr)

		_ = store.RemoveAllNamespacedPolicyReports()
		_, err = store.GetPolicyReport(npr.GetNamespace())
		require.Error(t, err, "Should have no results after CleanUp")
	})
}

func TestSaveMemoryReports(t *testing.T) {
	t.Run("Save ClusterPolicyReport (create)", func(t *testing.T) {
		store, err := report.NewMemoryPolicyReportStore()
		require.NoError(t, err)

		report := report.NewClusterPolicyReport("testing")
		err = store.SaveClusterPolicyReport(&report)
		// always updates ClusterPolicyReport, store initializes with blank
		// ClusterPolicReport
		require.NoError(t, err, "Should not return errors: %v", err)
	})

	t.Run("Save PolicyReport (create)", func(t *testing.T) {
		store, err := report.NewMemoryPolicyReportStore()
		require.NoError(t, err)

		npr2 := report.PolicyReport{
			v1alpha2.PolicyReport{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "polr-ns-test2",
					Namespace:         "test2",
					CreationTimestamp: metav1.Now(),
				},
				Summary: v1alpha2.PolicyReportSummary{},
				Results: []*v1alpha2.PolicyReportResult{},
			},
		}

		err = store.SavePolicyReport(&npr2)
		require.NoError(t, err, "Should not return errors: %v", err)

		_, err = store.GetPolicyReport(npr2.GetNamespace())
		require.NoError(t, err, "Should not return errors: %v", err)
	})

	t.Run("Save PolicyReport (update)", func(t *testing.T) {
		store, err := report.NewMemoryPolicyReportStore()
		require.NoError(t, err)

		// copy first resource version
		upr := npr
		// do some change
		upr.Summary = v1alpha2.PolicyReportSummary{Skip: 1}

		err = store.SavePolicyReport(&upr)
		require.NoError(t, err, "Should not return errors: %v", err)

		getObj, err := store.GetPolicyReport(npr.GetNamespace())
		require.NoError(t, err, "Should not return errors: %v", err)
		require.Equal(t, 1, getObj.Summary.Skip, "Expected Summary.Skip to be 1 after update. Object returned: %v", getObj)
	})
}
