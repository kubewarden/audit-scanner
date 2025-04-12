package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/kubewarden/audit-scanner/internal/k8s"
	"github.com/kubewarden/audit-scanner/internal/policies"
	"github.com/kubewarden/audit-scanner/internal/report"
	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"golang.org/x/sync/semaphore"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
)

const httpClientTimeout = 10 * time.Second

// Scanner verifies that existing resources don't violate any of the policies.
type Scanner struct {
	policiesClient    *policies.Client
	k8sClient         *k8s.Client
	policyReportStore *report.PolicyReportStore
	// http client used to make requests against the Policy Server
	httpClient               http.Client
	outputScan               bool
	disableStore             bool
	parallelNamespacesAudits int
	parallelResourcesAudits  int
	parallelPoliciesAudits   int
	logger                   *slog.Logger
}

// NewScanner creates a new scanner
// If insecureClient is false, it will read the caCertFile and add it to the in-app
// cert trust store. This gets used by the httpClient when connection to
// PolicyServers endpoints.
func NewScanner(config Config) (*Scanner, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Get the SystemCertPool to build an in-app cert pool from it
	// Continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	if config.TLS.CAFile != "" {
		caCert, err := os.ReadFile(config.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %q with CA cert: %w", config.TLS.CAFile, err)
		}
		// Append our cert to the in-app cert pool
		if ok := rootCAs.AppendCertsFromPEM(caCert); !ok {
			return nil, errors.New("failed to append cert to in-app RootCAs trust store")
		}
		config.Logger.Debug("appended cert file to in-app RootCAs trust store", slog.String("ca-cert", config.TLS.CAFile))
	}

	tlsConfig.RootCAs = rootCAs

	if config.TLS.ClientCertFile != "" && config.TLS.ClientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(config.TLS.ClientCertFile, config.TLS.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client certificate: %w", err)
		}
		config.Logger.Debug("appended cert file to in-app RootCAs trust store",
			slog.String("client-cert", config.TLS.ClientCertFile),
			slog.String("client-key", config.TLS.ClientKeyFile))

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if config.TLS.Insecure {
		config.Logger.Warn("connecting to PolicyServers endpoints without validating TLS connection")
	}
	tlsConfig.InsecureSkipVerify = config.TLS.Insecure

	httpClient := *http.DefaultClient
	httpClient.Timeout = httpClientTimeout
	httpClient.Transport = http.DefaultTransport
	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("failed to build httpClient: failed http.Transport type assertion")
	}

	transport.TLSClientConfig = tlsConfig

	// By dafault, the http client reuses connections. This causes
	// scaling issues when a PolicyServer instance is backed by multiple
	// replicas. In this scanerio, the requests are sent to the same
	// PolicyServer Pod, causing the load to be unevenly distributed.
	// To avoid this, we disable keep-alives, which ensures a
	// new connection is created for each evaluation request.
	transport.DisableKeepAlives = true

	return &Scanner{
		policiesClient:           config.PoliciesClient,
		k8sClient:                config.K8sClient,
		policyReportStore:        config.PolicyReportStore,
		httpClient:               httpClient,
		outputScan:               config.OutputScan,
		disableStore:             config.DisableStore,
		parallelNamespacesAudits: config.Parallelization.ParallelNamespacesAudits,
		parallelResourcesAudits:  config.Parallelization.ParallelResourcesAudits,
		parallelPoliciesAudits:   config.Parallelization.PoliciesAudits,
		logger:                   config.Logger.With("component", "scanner"),
	}, nil
}

// ScanNamespace scans resources for a given namespace.
// Returns errors if there's any when fetching policies or resources, but only
// logs them if there's a problem auditing the resource of saving the Report or
// Result, so it can continue with the next audit, or next Result.
func (s *Scanner) ScanNamespace(ctx context.Context, nsName, runUID string) error {
	s.logger.Info("namespace scan started",
		slog.Group("dict",
			slog.String("namespace", nsName),
			slog.String("RunUID", runUID),
			slog.Int("parallel-resources-audits", s.parallelResourcesAudits)))
	semaphore := semaphore.NewWeighted(int64(s.parallelResourcesAudits))
	var workers sync.WaitGroup

	namespace, err := s.k8sClient.GetNamespace(ctx, nsName)
	if err != nil {
		return err
	}
	policies, err := s.policiesClient.GetPoliciesByNamespace(ctx, namespace)
	if err != nil {
		s.logger.Error("failed to obtain auditable policies",
			slog.String("error", err.Error()),
			slog.String("namespace", nsName))
		return err
	}

	s.logger.Info("policy count",
		slog.String("namespace", nsName),
		slog.Group("dict"),
		slog.Int("policies-to-evaluate", policies.PolicyNum),
		slog.Int("policies-skipped", policies.SkippedNum),
		slog.Int("policies-errored", policies.ErroredNum))

	for gvr, pols := range policies.PoliciesByGVR {
		pager, err := s.k8sClient.GetResources(gvr, nsName)
		if err != nil {
			s.logger.Error("failed to get resources",
				slog.String("error", err.Error()),
				slog.String("gvr", gvr.String()),
				slog.String("ns", nsName))
		}

		err = pager.EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
			resource, ok := obj.(*unstructured.Unstructured)
			if !ok {
				return errors.New("failed to convert runtime.Object to *unstructured.Unstructured")
			}

			err := semaphore.Acquire(ctx, 1)
			if err != nil {
				return err
			}
			workers.Add(1)
			policiesToAudit := pols

			go func() {
				defer semaphore.Release(1)
				defer workers.Done()

				if err := s.auditResource(ctx, policiesToAudit, *resource, runUID, policies.SkippedNum, policies.ErroredNum); err != nil {
					s.logger.Error("error auditing resource",
						slog.String("error", err.Error()),
						slog.String("RunUID", runUID))
				}
			}()
			return nil
		})
		if err != nil {
			return err
		}
	}
	workers.Wait()
	if err := s.policyReportStore.DeleteOldPolicyReports(ctx, runUID, nsName); err != nil {
		s.logger.Error("error deleting old PolicyReports",
			slog.String("error", err.Error()),
			slog.String("RunUID", runUID))
	}
	s.logger.Info("Namespaced resources scan finished")
	return nil
}

// ScanAllNamespaces scans resources for all namespaces, except the ones in the skipped list.
// Returns errors if there's any when fetching policies or resources, but only
// logs them if there's a problem auditing the resource of saving the Report or
// Result, so it can continue with the next audit, or next Result.
func (s *Scanner) ScanAllNamespaces(ctx context.Context, runUID string) error {
	s.logger.Info("all-namespaces scan started",
		slog.Group("dict",
			slog.Int("parallel-namespaces-audits", s.parallelNamespacesAudits)))
	nsList, err := s.k8sClient.GetAuditedNamespaces(ctx)
	if err != nil {
		s.logger.Error("error scanning all namespaces", slog.String("error", err.Error()))
	}
	semaphore := semaphore.NewWeighted(int64(s.parallelNamespacesAudits))
	var workers sync.WaitGroup

	for _, namespace := range nsList.Items {
		workers.Add(1)
		err := semaphore.Acquire(ctx, 1)
		if err != nil {
			return err
		}
		namespaceName := namespace.Name

		go func() {
			defer semaphore.Release(1)
			defer workers.Done()

			if e := s.ScanNamespace(ctx, namespaceName, runUID); e != nil {
				s.logger.Error("error scanning namespace", slog.String("error", err.Error()), slog.String("ns", namespaceName))
				err = errors.Join(err, e)
			}
		}()
	}
	workers.Wait()

	s.logger.Info("all-namespaces scan finished")

	return err
}

// ScanClusterWideResources scans all cluster wide resources.
// Returns errors if there's any when fetching policies or resources, but only
// logs them if there's a problem auditing the resource of saving the Report or
// Result, so it can continue with the next audit, or next Result.
func (s *Scanner) ScanClusterWideResources(ctx context.Context, runUID string) error {
	s.logger.Info("clusterwide resources scan started", slog.String("RunUID", runUID))

	semaphore := semaphore.NewWeighted(int64(s.parallelResourcesAudits))
	var workers sync.WaitGroup

	policies, err := s.policiesClient.GetClusterWidePolicies(ctx)
	if err != nil {
		return err
	}

	s.logger.Info("cluster admission policies count",
		slog.Group("dict",
			slog.Int("policies-to-evaluate", policies.PolicyNum),
			slog.Int("policies-skipped", policies.SkippedNum),
			slog.Int("policies-errored", policies.ErroredNum),
			slog.Int("parallel-resources-audits", s.parallelResourcesAudits)))

	for gvr, pols := range policies.PoliciesByGVR {
		pager, err := s.k8sClient.GetResources(gvr, "")
		if err != nil {
			return err
		}

		err = pager.EachListItem(ctx, metav1.ListOptions{}, func(obj runtime.Object) error {
			resource, ok := obj.(*unstructured.Unstructured)
			if !ok {
				return errors.New("failed to convert runtime.Object to *unstructured.Unstructured")
			}

			workers.Add(1)
			err := semaphore.Acquire(ctx, 1)
			if err != nil {
				return err
			}
			policiesToAudit := pols

			go func() {
				defer semaphore.Release(1)
				defer workers.Done()

				s.auditClusterResource(ctx, policiesToAudit, *resource, runUID, policies.SkippedNum, policies.ErroredNum)
			}()

			return nil
		})
		if err != nil {
			return err
		}
	}

	workers.Wait()
	if err := s.policyReportStore.DeleteOldClusterPolicyReports(ctx, runUID); err != nil {
		s.logger.Error("error deleting old ClusterPolicyReports",
			slog.String("error", err.Error()),
			slog.String("RunUID", runUID))
	}
	s.logger.Info("Cluster-wide resources scan finished")

	return nil
}

type policyAuditResult struct {
	policy                  policiesv1.Policy
	admissionReviewResponse *admissionv1.AdmissionReview
	errored                 bool
}

//gocognit:ignore
func (s *Scanner) auditResource(ctx context.Context, policies []*policies.Policy, resource unstructured.Unstructured, runUID string, skippedPoliciesNum, erroredPoliciesNum int) error {
	s.logger.Info("audit resource",
		slog.String("resource", resource.GetName()),
		slog.Group("dict"),
		slog.Int("policies-to-evaluate", len(policies)),
		slog.Int("parallel-policies-audit", s.parallelPoliciesAudits))

	semaphore := semaphore.NewWeighted(int64(s.parallelPoliciesAudits))
	var workers sync.WaitGroup
	auditResults := make(chan policyAuditResult, len(policies))

	for _, policyToUse := range policies {
		err := semaphore.Acquire(ctx, 1)
		if err != nil {
			return err
		}
		workers.Add(1)

		url := policyToUse.PolicyServer
		policy := policyToUse.Policy

		go func() {
			defer semaphore.Release(1)
			defer workers.Done()

			matches, err := policyMatches(policy, resource)
			if err != nil {
				s.logger.Error("error matching policy to resource", slog.String("error", err.Error()))
			}

			if !matches {
				return
			}

			admissionReviewRequest := newAdmissionReview(resource)
			admissionReviewResponse, responseErr := s.sendAdmissionReviewToPolicyServer(ctx, url, admissionReviewRequest)
			errored := false

			if responseErr != nil {
				errored = true
				// log responseErr, will end in PolicyReportResult too
				s.logger.Error("error sending AdmissionReview to PolicyServer",
					slog.String("error", responseErr.Error()),
					slog.Group("response",
						slog.String("admissionRequest-name", admissionReviewRequest.Request.Name),
						slog.String("policy", policy.GetName()),
						slog.String("resource", resource.GetName())))
			} else if admissionReviewResponse.Response.Result != nil &&
				admissionReviewResponse.Response.Result.Code == 500 {
				errored = true
				// log Result.Message, will end in PolicyReportResult too
				s.logger.Error("error evaluating Policy in PolicyServer", slog.String("error", errors.New(admissionReviewResponse.Response.Result.Message).Error()),
					slog.Group("response",
						slog.String("admissionRequest-name", admissionReviewRequest.Request.Name),
						slog.String("policy", policy.GetName()),
						slog.String("resource", resource.GetName())))
			}

			if !errored {
				s.logger.Debug("audit review response",
					slog.Group("response",
						slog.String("uid", string(admissionReviewResponse.Response.UID)),
						slog.String("policy", policy.GetName()),
						slog.String("resource", resource.GetName()),
						slog.Bool("allowed", admissionReviewResponse.Response.Allowed)))
			}

			auditResults <- policyAuditResult{
				policy,
				admissionReviewResponse,
				errored,
			}
		}()
	}
	workers.Wait()
	close(auditResults)

	policyReport := report.NewPolicyReport(runUID, resource)
	policyReport.Summary.Skip = skippedPoliciesNum
	policyReport.Summary.Error = erroredPoliciesNum
	for res := range auditResults {
		report.AddResultToPolicyReport(policyReport, res.policy, res.admissionReviewResponse, res.errored)
	}

	if s.outputScan {
		policyReportJSON, err := json.Marshal(policyReport)
		if err != nil {
			s.logger.Error("error while marshalling PolicyReport to JSON, skipping output scan", slog.String("error", err.Error()))
		}

		s.logger.Info("PolicyReport summary", slog.String("report", string(policyReportJSON)))
	}

	if !s.disableStore {
		err := s.policyReportStore.CreateOrPatchPolicyReport(ctx, policyReport)
		if err != nil {
			s.logger.Error("error adding PolicyReport to store.", slog.String("error", err.Error()))
		}
	}

	return nil
}

func (s *Scanner) auditClusterResource(ctx context.Context, policies []*policies.Policy, resource unstructured.Unstructured, runUID string, skippedPoliciesNum, erroredPoliciesNum int) {
	s.logger.Info("audit clusterwide resource",
		slog.String("resource", resource.GetName()),
		slog.Group("dict",
			slog.Int("policies-to-evaluate", len(policies))))

	clusterPolicyReport := report.NewClusterPolicyReport(runUID, resource)
	clusterPolicyReport.Summary.Skip = skippedPoliciesNum
	clusterPolicyReport.Summary.Error = erroredPoliciesNum
	for _, p := range policies {
		url := p.PolicyServer
		policy := p.Policy

		matches, err := policyMatches(policy, resource)
		if err != nil {
			s.logger.Error("error matching policy to resource", slog.String("error", err.Error()))
		}

		if !matches {
			continue
		}

		admissionReviewRequest := newAdmissionReview(resource)
		admissionReviewResponse, responseErr := s.sendAdmissionReviewToPolicyServer(ctx, url, admissionReviewRequest)
		errored := false

		if responseErr != nil {
			errored = true
			// log error, will end in ClusterPolicyReportResult too
			s.logger.Error("error sending AdmissionReview to PolicyServer", slog.String("error", responseErr.Error()),
				slog.Group("response",
					slog.String("admissionRequest name", admissionReviewRequest.Request.Name),
					slog.String("policy", policy.GetName()),
					slog.String("resource", resource.GetName())))
		} else if admissionReviewResponse.Response.Result != nil &&
			admissionReviewResponse.Response.Result.Code == 500 {
			errored = true
			// log Result.Message, will end in PolicyReportResult too
			s.logger.Error("error evaluating Policy in PolicyServer", slog.String("error", errors.New(admissionReviewResponse.Response.Result.Message).Error()),
				slog.Group("response",
					slog.String("admissionRequest-name", admissionReviewRequest.Request.Name),
					slog.String("policy", policy.GetName()),
					slog.String("resource", resource.GetName())))
		}

		if !errored {
			s.logger.Debug("audit review response",
				slog.Group("response",
					slog.String("uid", string(admissionReviewResponse.Response.UID)),
					slog.String("policy", policy.GetName()),
					slog.String("resource", resource.GetName()),
					slog.Bool("allowed", admissionReviewResponse.Response.Allowed)))
		}

		report.AddResultToClusterPolicyReport(clusterPolicyReport, policy, admissionReviewResponse, errored)
	}

	if s.outputScan {
		clusterPolicyReportJSON, err := json.Marshal(clusterPolicyReport)
		if err != nil {
			s.logger.Error("error while marshalling ClusterPolicyReport to JSON, skipping output scan", slog.String("error", err.Error()))
		}

		s.logger.Info("ClusterPolicyReport summary", slog.String("report", string(clusterPolicyReportJSON)))
	}

	if !s.disableStore {
		err := s.policyReportStore.CreateOrPatchClusterPolicyReport(ctx, clusterPolicyReport)
		if err != nil {
			s.logger.Error("error adding ClusterPolicyReport to store", slog.String("error", err.Error()))
		}
	}
}

func policyMatches(policy policiesv1.Policy, resource unstructured.Unstructured) (bool, error) {
	if policy.GetObjectSelector() == nil {
		return true, nil
	}

	selector, err := metav1.LabelSelectorAsSelector(policy.GetObjectSelector())
	if err != nil {
		return false, err
	}

	labels := labels.Set(resource.GetLabels())
	if !selector.Matches(labels) {
		return false, nil
	}

	return true, nil
}

func (s *Scanner) sendAdmissionReviewToPolicyServer(ctx context.Context, url *url.URL, admissionRequest *admissionv1.AdmissionReview) (*admissionv1.AdmissionReview, error) {
	payload, err := json.Marshal(admissionRequest)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url.String(), bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	res, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read body of response: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d body: %s", res.StatusCode, body)
	}

	admissionReview := admissionv1.AdmissionReview{}
	err = json.Unmarshal(body, &admissionReview)
	if err != nil {
		return nil, fmt.Errorf("cannot deserialize the audit review response: %w", err)
	}
	return &admissionReview, nil
}
