package report

import (
	"encoding/json"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"

	"github.com/kubewarden/audit-scanner/internal/constants"
	policiesv1 "github.com/kubewarden/kubewarden-controller/pkg/apis/policies/v1"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	admv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type PolicyReport struct {
	v1alpha2.PolicyReport
}
type ClusterPolicyReport struct {
	v1alpha2.ClusterPolicyReport
}

const (
	// Status specifies state of a policy result
	StatusPass  = "pass"
	StatusFail  = "fail"
	StatusWarn  = "warn"
	StatusError = "error"
	StatusSkip  = "skip"

	// Severity specifies severity of a policy result
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"

	// Category specifies the category of a policy result
	TypeMutating     = "mutating"
	TypeValidating   = "validating"
	TypeContextAware = "context-aware"
	ValueTypeTrue    = "true"

	LabelAppManagedBy = "app.kubernetes.io/managed-by"
	LabelApp          = "kubewarden"
)

func NewClusterPolicyReport(name string) ClusterPolicyReport {
	labels := map[string]string{}
	labels[LabelAppManagedBy] = LabelApp
	return ClusterPolicyReport{
		ClusterPolicyReport: v1alpha2.ClusterPolicyReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:              PrefixNameClusterPolicyReport + name,
				CreationTimestamp: metav1.Now(),
				Labels:            labels,
			},
			Summary: v1alpha2.PolicyReportSummary{
				Pass:  0, // count of policies with requirements met
				Fail:  0, // count of policies with requirements not met
				Warn:  0, // not used for now
				Error: 0, // count of policies that couldn't be evaluated
				Skip:  0, // count of policies that were not selected for evaluation
			},
			Results: []*v1alpha2.PolicyReportResult{},
		},
	}
}

func NewPolicyReport(namespace *v1.Namespace) PolicyReport {
	labels := map[string]string{}
	labels[LabelAppManagedBy] = LabelApp
	return PolicyReport{
		PolicyReport: v1alpha2.PolicyReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:              PrefixNamePolicyReport + namespace.Name,
				Namespace:         namespace.Name,
				CreationTimestamp: metav1.Now(),
				Labels:            labels,
			},
			Scope: &v1.ObjectReference{
				Kind:            namespace.Kind,
				Namespace:       "",
				Name:            namespace.Name,
				UID:             namespace.UID,
				APIVersion:      namespace.APIVersion,
				ResourceVersion: namespace.ResourceVersion,
			},
			Summary: v1alpha2.PolicyReportSummary{
				Pass:  0, // count of policies with requirements met
				Fail:  0, // count of policies with requirements not met
				Warn:  0, // not used for now
				Error: 0, // count of policies that couldn't be evaluated
				Skip:  0, // count of policies that were not selected for evaluation
			},
			Results: []*v1alpha2.PolicyReportResult{},
		},
	}
}

// GetSummaryJSON gets the report.Summary formatted in JSON. Useful for logging
func (r *PolicyReport) GetSummaryJSON() (string, error) {
	marshaled, err := json.Marshal(r.Summary)
	if err != nil {
		return "error marshalling summary", err
	}
	return string(marshaled), nil
}

// GetSummaryJSON gets the report.Summary formatted in JSON. Useful for logging
func (r *ClusterPolicyReport) GetSummaryJSON() (string, error) {
	marshaled, err := json.Marshal(r.Summary)
	if err != nil {
		return "error marshalling summary", err
	}
	return string(marshaled), nil
}

func (r *PolicyReport) AddResult( //nolint:dupl
	policy policiesv1.Policy, resource unstructured.Unstructured,
	auditResponse *admv1.AdmissionReview, responseErr error,
) {
	result := newPolicyReportResult(policy, resource, auditResponse, responseErr)
	switch result.Result {
	case StatusFail:
		r.Summary.Fail++
	case StatusError:
		r.Summary.Error++
	case StatusPass:
		r.Summary.Pass++
	default:
		// this should never happen
		log.Error().
			Str("report name", r.Name).
			Dict("result", zerolog.Dict().
				Str("policy", policy.GetName()).
				Str("resource", resource.GetName()).
				Str("result", string(result.Result)),
			).Msg("result unknown")
	}
	r.Results = append(r.Results, result)
	log.Debug().
		Str("report name", r.Name).
		Dict("result", zerolog.Dict().
			Str("policy", policy.GetName()).
			Str("resource", resource.GetName()).
			Bool("allowed", auditResponse.Response.Allowed).
			Str("result", string(result.Result)),
		).Msg("added result to report")
}

func (r *ClusterPolicyReport) AddResult( //nolint:dupl
	policy policiesv1.Policy, resource unstructured.Unstructured,
	auditResponse *admv1.AdmissionReview, responseErr error,
) {
	result := newPolicyReportResult(policy, resource, auditResponse, responseErr)
	switch result.Result {
	case StatusFail:
		r.Summary.Fail++
	case StatusError:
		r.Summary.Error++
	case StatusPass:
		r.Summary.Pass++
	default:
		// this should never happen
		log.Error().Str("report name", r.Name).Dict("result", zerolog.Dict().
			Str("policy", policy.GetName()).Str("resource", resource.GetName()).
			Str("result", string(result.Result)),
		).Msg("result unknown")
	}
	r.Results = append(r.Results, result)
	log.Debug().Str("report name", r.Name).Dict("result", zerolog.Dict().
		Str("policy", policy.GetName()).Str("resource", resource.GetName()).
		Bool("allowed", auditResponse.Response.Allowed).
		Str("result", string(result.Result)),
	).Msg("added result to report")
}

func newPolicyReportResult( //nolint:funlen,cyclop
	policy policiesv1.Policy, resource unstructured.Unstructured,
	auditResponse *admv1.AdmissionReview, responseErr error,
) *v1alpha2.PolicyReportResult {
	var result v1alpha2.PolicyResult
	var description string
	if responseErr != nil {
		result = StatusError
		description = auditResponse.Response.Result.Message
	} else {
		if auditResponse.Response.Allowed {
			result = StatusPass
		} else {
			result = StatusFail
			description = auditResponse.Response.Result.Message
		}
	}

	var name string
	switch policy.GetObjectKind().GroupVersionKind() {
	case schema.GroupVersionKind{
		Group:   constants.KubewardenPoliciesGroup,
		Version: constants.KubewardenPoliciesVersion,
		Kind:    constants.KubewardenKindClusterAdmissionPolicy,
	}:
		name = "cap-" + policy.GetName()
	case schema.GroupVersionKind{
		Group:   constants.KubewardenPoliciesGroup,
		Version: constants.KubewardenPoliciesVersion,
		Kind:    constants.KubewardenKindAdmissionPolicy,
	}:
		name = "ap-" + policy.GetName()
	default: // this never happens
		log.Fatal().Msg("no policy found when creating PolicyReportResult")
	}

	time := metav1.Now()
	timestamp := *time.ProtoTime()

	var severity v1alpha2.PolicyResultSeverity
	var scored bool
	if policy.GetPolicyMode() == policiesv1.PolicyMode(policiesv1.PolicyModeStatusMonitor) {
		scored = true
		severity = SeverityInfo
	} else {
		if sev, present := policy.GetSeverity(); present {
			scored = true
			switch sev {
			case SeverityCritical:
				severity = SeverityCritical
			case SeverityHigh:
				severity = SeverityHigh
			case SeverityMedium:
				severity = SeverityMedium
			case SeverityLow:
				severity = SeverityLow
			default:
				// this should never happen
				log.Error().
					Dict("result", zerolog.Dict().
						Str("policy", policy.GetName()).
						Str("resource", resource.GetName()).
						Bool("allowed", auditResponse.Response.Allowed).
						Str("severity", sev),
					).Msg("severity unknown")
			}
		}
	}

	var category string
	if cat, present := policy.GetCategory(); present {
		category = cat
	}

	properties := map[string]string{}
	if policy.IsMutating() {
		properties[TypeMutating] = ValueTypeTrue
	} else {
		properties[TypeValidating] = ValueTypeTrue
	}
	if policy.IsContextAware() {
		properties[TypeContextAware] = ValueTypeTrue
	}

	rule := policy.GetName()

	resourceObjectReference := &v1.ObjectReference{
		Kind:            resource.GetKind(),
		Namespace:       resource.GetNamespace(),
		Name:            resource.GetName(),
		UID:             resource.GetUID(),
		APIVersion:      resource.GetAPIVersion(),
		ResourceVersion: resource.GetResourceVersion(),
	}

	return &v1alpha2.PolicyReportResult{
		Source:   PolicyReportSource,
		Policy:   name,     // either cap-policy_name or ap-policy_name
		Rule:     rule,     // policy name
		Category: category, // either validating, or mutating and validating
		Severity: severity, // either info for monitor or empty
		// Timestamp shouldn't be used in go structs, and only gives seconds
		// https://github.com/kubernetes/apimachinery/blob/v0.27.2/pkg/apis/meta/v1/time_proto.go#LL48C9-L48C9
		Timestamp:       timestamp, // time the result was computed
		Result:          result,    // pass, fail, error
		Scored:          scored,
		Subjects:        []*v1.ObjectReference{resourceObjectReference}, // reference to object evaluated
		SubjectSelector: &metav1.LabelSelector{},
		Description:     description, // output message of the policy
		Properties:      properties,
	}
}
