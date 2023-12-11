package report

const (
	KUBERNETES string = "kubernetes"
	MEMORY     string = "memory"
)

var SupportedTypes = [2]string{KUBERNETES, MEMORY}

// PolicyReportStore caches the latest version of PolicyReports
// There is 2 different stores available:
//   - KubernetesPolicyReportStore, which uses K8s/etcd backend only
//   - MemoryPolicyReportStore, which uses in-memory cache
type PolicyReportStore interface {
	// GetPolicyReport returns the Policy Report defined inside a given namespace.
	// An empty PolicyReport is returned when nothing is found
	GetPolicyReport(namespace string) (PolicyReport, error)

	// GetClusterPolicyReport gets the ClusterPolicyReport
	GetClusterPolicyReport(name string) (ClusterPolicyReport, error)

	// RemovePolicyReport removes a PolicyReport from a given namespace
	RemovePolicyReport(namespace string) error

	// RemoveAllNamespacedPolicyReports deletes all namespaced PolicyReports
	RemoveAllNamespacedPolicyReports() error

	// SavePolicyReport instantiates the passed namespaced PolicyReport if it doesn't exist, or
	// updates it if one is found
	SavePolicyReport(report *PolicyReport) error

	// SaveClusterPolicyReport instantiates the ClusterPolicyReport if it doesn't exist, or
	// updates it one is found
	SaveClusterPolicyReport(report *ClusterPolicyReport) error

	// ToJSON marshals the contents of the store into a JSON string
	ToJSON() (string, error)
}
