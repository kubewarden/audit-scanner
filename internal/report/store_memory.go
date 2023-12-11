package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/exp/maps"

	"github.com/kubewarden/audit-scanner/internal/constants"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type MemoryPolicyReportStore struct {
	// prCache is a map between a namespace and a PolicyReport
	prCache map[string]PolicyReport

	// cprCache is a map between a name and a ClusterPolicyReport
	cprCache map[string]ClusterPolicyReport

	mutex sync.RWMutex
}

func NewMemoryPolicyReportStore() (*MemoryPolicyReportStore, error) {
	return &MemoryPolicyReportStore{
		prCache:  make(map[string]PolicyReport),
		cprCache: make(map[string]ClusterPolicyReport),
	}, nil
}

func (s *MemoryPolicyReportStore) GetPolicyReport(namespace string) (PolicyReport, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	report, found := s.prCache[namespace]

	if !found {
		return PolicyReport{}, constants.ErrResourceNotFound
	}

	log.Debug().Dict("dict", zerolog.Dict().
		Str("report name", report.GetName()).
		Str("report ns", report.GetNamespace()).
		Str("report resourceVersion", report.GetResourceVersion())).
		Msg("PolicyReport found")
	return report, nil
}

func (s *MemoryPolicyReportStore) GetClusterPolicyReport(name string) (ClusterPolicyReport, error) {
	if !strings.HasPrefix(name, PrefixNameClusterPolicyReport) {
		name = getClusterReportName(name)
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()
	report, found := s.cprCache[name]

	if !found {
		return ClusterPolicyReport{}, constants.ErrResourceNotFound
	}

	return report, nil
}

func (s *MemoryPolicyReportStore) RemovePolicyReport(namespace string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.prCache, namespace)

	return nil
}

func (s *MemoryPolicyReportStore) RemoveAllNamespacedPolicyReports() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.prCache = make(map[string]PolicyReport)

	return nil
}

func (s *MemoryPolicyReportStore) updatePolicyReport(report *PolicyReport) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.prCache[report.GetNamespace()] = *report

	summary, _ := report.GetSummaryJSON()
	log.Info().
		Dict("dict", zerolog.Dict().
			Str("report name", report.GetName()).
			Str("report ns", report.GetNamespace()).
			Str("report resourceVersion", report.GetResourceVersion()).
			Str("summary", summary),
		).Msg("updated PolicyReport")
	return nil
}

func (s *MemoryPolicyReportStore) updateClusterPolicyReport(report *ClusterPolicyReport) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.cprCache[report.GetName()] = *report

	summary, _ := report.GetSummaryJSON()
	log.Info().
		Dict("dict", zerolog.Dict().
			Str("report name", report.GetName()).
			Str("report ns", report.GetNamespace()).
			Str("summary", summary),
		).Msg("updated ClusterPolicyReport")
	return nil
}

func (s *MemoryPolicyReportStore) SavePolicyReport(report *PolicyReport) error {
	// Check for existing Policy Report
	_, getErr := s.GetPolicyReport(report.GetNamespace())
	if getErr != nil {
		// Create new Policy Report if not found
		if errors.Is(getErr, constants.ErrResourceNotFound) {
			// Update will create a new one if it doesn't exist
			return s.updatePolicyReport(report)
		}
		return getErr
	}

	// get the latest report version to be updated
	latestReport, err := s.GetPolicyReport(report.GetNamespace())
	if err != nil {
		return fmt.Errorf("update failed: %w", err)
	}

	// Update existing Policy Report
	latestReport.Summary = report.Summary
	latestReport.Results = report.Results
	return s.updatePolicyReport(&latestReport)
}

func (s *MemoryPolicyReportStore) SaveClusterPolicyReport(report *ClusterPolicyReport) error {
	// Check for existing Policy Report
	_, getErr := s.GetClusterPolicyReport(report.GetName())
	if getErr != nil {
		// Create new Policy Report if not found
		if errors.Is(getErr, constants.ErrResourceNotFound) {
			// Update will create a new one if it doesn't exist
			return s.updateClusterPolicyReport(report)
		}
		return getErr
	}

	// get the latest report version to be updated
	latestReport, err := s.GetClusterPolicyReport(report.GetName())
	if err != nil {
		return fmt.Errorf("update failed: %w", err)
	}

	// Update existing Policy Report
	latestReport.Summary = report.Summary
	latestReport.Results = report.Results
	return s.updateClusterPolicyReport(&latestReport)
}

func (s *MemoryPolicyReportStore) listPolicyReports() ([]PolicyReport, error) { //nolint:unparam // respect the interface
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return maps.Values(s.prCache), nil
}

func (s *MemoryPolicyReportStore) ToJSON() (string, error) {
	recapJSON := make(map[string]interface{})
	clusterReport, err := s.GetClusterPolicyReport(constants.DefaultClusterwideReportName)
	if err != nil {
		log.Error().Err(err).Msg("error fetching ClusterPolicyReport. Ignoring this error to allow user to read the namespaced reports")
	}
	recapJSON["cluster"] = clusterReport
	nsReports, err := s.listPolicyReports()
	if err != nil {
		return "", err
	}
	recapJSON["namespaces"] = nsReports

	marshaled, err := json.Marshal(recapJSON)
	if err != nil {
		return "", err
	}
	return string(marshaled), nil
}
