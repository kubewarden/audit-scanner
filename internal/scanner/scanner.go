package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/kubewarden/audit-scanner/internal/constants"
	"github.com/kubewarden/audit-scanner/internal/report"
	"github.com/kubewarden/audit-scanner/internal/resources"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	admv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/core/v1"
)

// A PoliciesFetcher interacts with the kubernetes api to return Kubewarden policies
type PoliciesFetcher interface {
	// GetPoliciesForANamespace gets all auditable policies for a given
	// namespace, and the number of skipped policies
	GetPoliciesForANamespace(namespace string) ([]policiesv1.Policy, int, error)
	// GetNamespace gets a given namespace
	GetNamespace(namespace string) (*v1.Namespace, error)
	// GetAuditedNamespaces gets all namespaces, minus those in the skipped ns list
	GetAuditedNamespaces() (*v1.NamespaceList, error)
	// GetPoliciesForAllNamespaces gets all auditable policies for all
	// namespaces, and the number of skipped policies
	GetPoliciesForAllNamespaces() ([]policiesv1.Policy, int, error)
	// Get all auditable ClusterAdmissionPolicies and the number of skipped policies
	GetClusterAdmissionPolicies() ([]policiesv1.Policy, int, error)
}

type ResourcesFetcher interface {
	GetResourcesForPolicies(ctx context.Context, policies []policiesv1.Policy, namespace string) ([]resources.AuditableResources, error)
	// GetPolicyServerURLRunningPolicy gets the URL used to send API requests to the policy server
	GetPolicyServerURLRunningPolicy(ctx context.Context, policy policiesv1.Policy) (*url.URL, error)
	// Get Cluster wide resources evaluated by the given policies
	GetClusterWideResourcesForPolicies(ctx context.Context, policies []policiesv1.Policy) ([]resources.AuditableResources, error)
}

// A Scanner verifies that existing resources don't violate any of the policies
type Scanner struct {
	policiesFetcher  PoliciesFetcher
	resourcesFetcher ResourcesFetcher
	reportStore      report.PolicyReportStore
	// http client used to make requests against the Policy Server
	httpClient http.Client
	printJSON  bool
}

// NewScanner creates a new scanner with the PoliciesFetcher provided
func NewScanner(policiesFetcher PoliciesFetcher, resourcesFetcher ResourcesFetcher, printJSON bool) (*Scanner, error) {
	report, err := report.NewPolicyReportStore()
	if err != nil {
		return nil, err
	}
	return &Scanner{policiesFetcher, resourcesFetcher, *report, http.Client{}, printJSON}, nil
}

// ScanNamespace scans resources for a given namespace
func (s *Scanner) ScanNamespace(nsName string) error {
	log.Info().Str("namespace", nsName).Msg("namespace scan started")

	namespace, err := s.policiesFetcher.GetNamespace(nsName)
	if err != nil {
		return err
	}

	policies, skippedNum, err := s.policiesFetcher.GetPoliciesForANamespace(nsName)
	if err != nil {
		return err
	}
	log.Info().
		Str("namespace", nsName).
		Dict("dict", zerolog.Dict().
			Int("policies to evaluate", len(policies)).
			Int("policies skipped", skippedNum),
		).Msg("policy count")

	auditableResources, err := s.resourcesFetcher.GetResourcesForPolicies(context.Background(), policies, nsName)
	if err != nil {
		return err
	}

	// create PolicyReport
	namespacedsReport := report.NewPolicyReport(namespace)
	namespacedsReport.Summary.Skip = skippedNum
	// old policy report to be used as cache
	previousNamespacedReport, err := s.reportStore.GetPolicyReport(nsName)
	if err != nil {
		log.Error().Err(err).Str("namespace", nsName).
			Msg("error getting previous PolicyReport from store")
	}

	// Iterate through all auditableResources. Each item contains a list of resources and the policies that would need
	// to evaluate them.
	for i := range auditableResources {
		auditResource(&auditableResources[i], s.resourcesFetcher, &s.httpClient, &namespacedsReport, &previousNamespacedReport)
		err = s.reportStore.SavePolicyReport(&namespacedsReport)
		if err != nil {
			log.Error().Err(err).Msg("error adding PolicyReport to store")
		}
	}
	log.Info().Str("namespace", nsName).Msg("namespace scan finished")

	if s.printJSON {
		str, err := s.reportStore.ToJSON()
		if err != nil {
			log.Error().Err(err).Msg("error marshaling reportStore to JSON")
		}
		fmt.Println(str)
	}
	return nil
}

// ScanAllNamespaces scans resources for all namespaces. Skips those namespaces
// passed in the skipped list on the policy fetcher.
// Returns errors if there's any when fetching policies or resources, but only
// logs them if there's a problem auditing the resource of saving the Report or
// Result, so it can continue with the next audit, or next Result.
func (s *Scanner) ScanAllNamespaces() error {
	log.Info().Msg("all-namespaces scan started")
	nsList, err := s.policiesFetcher.GetAuditedNamespaces()
	if err != nil {
		log.Error().Err(err).Msg("error scanning all namespaces")
	}
	var errs error
	for _, ns := range nsList.Items {
		if err := s.ScanNamespace(ns.Name); err != nil {
			log.Error().Err(err).Str("ns", ns.Name).Msg("error scanning namespace")
			errs = errors.New(errs.Error() + err.Error())
		}
	}
	log.Info().Msg("all-namespaces scan finished")
	return errs
}

func (s *Scanner) ScanClusterWideResources() error {
	log.Info().Msg("cluster wide scan started")
	policies, skippedNum, err := s.policiesFetcher.GetClusterAdmissionPolicies()
	if err != nil {
		return err
	}
	log.Debug().
		Dict("dict", zerolog.Dict().
			Int("policies to evaluate", len(policies)).
			Int("policies skipped", skippedNum),
		).Msg("cluster admission policies count")
	auditableResources, err := s.resourcesFetcher.GetClusterWideResourcesForPolicies(context.Background(), policies)
	if err != nil {
		return err
	}
	// create PolicyReport
	clusterReport := report.NewClusterPolicyReport(constants.DefaultClusterwideReportName)
	clusterReport.Summary.Skip = skippedNum
	// old policy report to be used as cache
	previousClusterReport, err := s.reportStore.GetClusterPolicyReport(constants.DefaultClusterwideReportName)
	if err != nil {
		log.Error().Err(err).Msg("error getting ClusterPolicyReport from store")
	}
	// Iterate through all auditableResources. Each item contains a list of resources and the policies that would need
	// to evaluate them.
	for i := range auditableResources {
		auditClusterResource(&auditableResources[i], s.resourcesFetcher, &s.httpClient, &clusterReport, &previousClusterReport)
	}
	log.Info().Msg("scan finished")
	err = s.reportStore.SaveClusterPolicyReport(&clusterReport)
	if err != nil {
		log.Error().Err(err).Msg("error adding PolicyReport to store")
	}
	if s.printJSON {
		str, err := s.reportStore.ToJSON()
		if err != nil {
			log.Error().Err(err).Msg("error marshaling reportStore to JSON")
		}
		fmt.Println(str)
	}
	return nil
}

func auditClusterResource(resource *resources.AuditableResources, resourcesFetcher ResourcesFetcher, httpClient *http.Client, clusterReport, previousClusterReport *report.ClusterPolicyReport) {
	for _, policy := range resource.Policies {
		url, err := resourcesFetcher.GetPolicyServerURLRunningPolicy(context.Background(), policy)
		if err != nil {
			// TODO what's the better thing to do here?
			log.Error().Err(err).Msg("cannot get policy server url")
			continue
		}
		for _, resource := range resource.Resources {
			if result := previousClusterReport.GetReusablePolicyReportResult(policy, resource); result != nil {
				// We have a result from the same policy version for the same resource instance.
				// Skip the evaluation
				clusterReport.AddResult(result)
				log.Debug().Dict("skip-evaluation", zerolog.Dict().
					Str("policy", policy.GetName()).
					Str("policyResourceVersion", policy.GetResourceVersion()).
					Str("policyUID", string(policy.GetUID())).
					Str("resource", resource.GetName()).
					Str("resourceResourceVersion", resource.GetResourceVersion()),
				).Msg("Previous result found. Reuse result")
				continue
			}
			admissionRequest := resources.GenerateAdmissionReview(resource)
			auditResponse, responseErr := sendAdmissionReviewToPolicyServer(url, admissionRequest, httpClient)
			if responseErr != nil {
				// log error, will end in ClusterPolicyReportResult too
				log.Error().Err(responseErr).Dict("response", zerolog.Dict().
					Str("admissionRequest name", admissionRequest.Request.Name).
					Str("policy", policy.GetName()).
					Str("resource", resource.GetName()),
				).
					Msg("error sending AdmissionReview to PolicyServer")
			} else {
				log.Debug().Dict("response", zerolog.Dict().
					Str("uid", string(auditResponse.Response.UID)).
					Bool("allowed", auditResponse.Response.Allowed).
					Str("policy", policy.GetName()).
					Str("resource", resource.GetName()),
				).
					Msg("audit review response")
				result := clusterReport.CreateResult(policy, resource, auditResponse, responseErr)
				clusterReport.AddResult(result)
			}
		}
	}
}

// auditResource sends the requests to the Policy Server to evaluate the auditable resources.
// It will iterate over the policies which should evaluate the resource, get the URL to the service of the policy
// server running the policy, creates the AdmissionReview payload and send the request to the policy server for evaluation
func auditResource(toBeAudited *resources.AuditableResources, resourcesFetcher ResourcesFetcher, httpClient *http.Client, nsReport, previousNsReport *report.PolicyReport) {
	for _, policy := range toBeAudited.Policies {
		url, err := resourcesFetcher.GetPolicyServerURLRunningPolicy(context.Background(), policy)
		if err != nil {
			// TODO what's the better thing to do here?
			log.Error().Err(err)
			continue
		}
		for _, resource := range toBeAudited.Resources {
			if result := previousNsReport.GetReusablePolicyReportResult(policy, resource); result != nil {
				// We have a result from the same policy version for the same resource instance.
				// Skip the evaluation
				nsReport.AddResult(result)
				log.Debug().Dict("skip-evaluation", zerolog.Dict().
					Str("policy", policy.GetName()).
					Str("policyResourceVersion", policy.GetResourceVersion()).
					Str("policyUID", string(policy.GetUID())).
					Str("resource", resource.GetName()).
					Str("resourceResourceVersion", resource.GetResourceVersion()),
				).Msg("Previous result found. Reuse result")
				continue
			}

			admissionRequest := resources.GenerateAdmissionReview(resource)
			auditResponse, responseErr := sendAdmissionReviewToPolicyServer(url, admissionRequest, httpClient)
			if responseErr != nil {
				// log responseErr, will end in PolicyReportResult too
				log.Error().Err(responseErr).Dict("response", zerolog.Dict().
					Str("admissionRequest name", admissionRequest.Request.Name).
					Str("policy", policy.GetName()).
					Str("resource", resource.GetName()),
				).
					Msg("error sending AdmissionReview to PolicyServer")
			} else {
				log.Debug().Dict("response", zerolog.Dict().
					Str("uid", string(auditResponse.Response.UID)).
					Str("policy", policy.GetName()).
					Str("resource", resource.GetName()).
					Bool("allowed", auditResponse.Response.Allowed),
				).
					Msg("audit review response")
				result := nsReport.CreateResult(policy, resource, auditResponse, responseErr)
				nsReport.AddResult(result)
			}
		}
	}
}

func sendAdmissionReviewToPolicyServer(url *url.URL, admissionRequest *admv1.AdmissionReview, httpClient *http.Client) (*admv1.AdmissionReview, error) {
	payload, err := json.Marshal(admissionRequest)

	if err != nil {
		return nil, err
	}
	// TODO remove the following line and properly configure the certificates
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, url.String(), bytes.NewBuffer(payload))
	res, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read body of response: %w", err)
	}
	if res.StatusCode > 299 {
		return nil, fmt.Errorf("response failed with status code: %d and\nbody: %s", res.StatusCode, body)
	}
	admissionReview := admv1.AdmissionReview{}
	err = json.Unmarshal(body, &admissionReview)
	if err != nil {
		return nil, fmt.Errorf("cannot deserialize the audit review response: %w", err)
	}
	return &admissionReview, nil
}
