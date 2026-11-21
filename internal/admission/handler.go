// Package admission implements the HTTP side of a Kubernetes validating admission webhook.
package admission

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/santoshmyakala/k8s-guardrails-webhook/internal/policy"
)

// The API server sends at most ~3 MiB objects; anything bigger is not a real AdmissionReview.
const maxBodyBytes = 4 << 20

// Metrics are the webhook's Prometheus series.
type Metrics struct {
	Requests   *prometheus.CounterVec
	Violations *prometheus.CounterVec
	BreakGlass *prometheus.CounterVec
	Duration   prometheus.Histogram
}

// NewMetrics registers the webhook's metrics.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "guardrails_admission_requests_total",
			Help: "Admission requests by kind, operation and decision (allowed, denied, warned, grandfathered, exempt, break-glass, error).",
		}, []string{"kind", "operation", "decision"}),
		Violations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "guardrails_violations_total",
			Help: "Policy violations found, by rule and namespace.",
		}, []string{"rule", "namespace"}),
		BreakGlass: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "guardrails_break_glass_total",
			Help: "Non-compliant workloads admitted with the break-glass annotation.",
		}, []string{"namespace"}),
		Duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "guardrails_admission_duration_seconds",
			Help:    "Time to evaluate an admission request.",
			Buckets: []float64{.0005, .001, .0025, .005, .01, .025, .05, .1, .25},
		}),
	}
	reg.MustRegister(m.Requests, m.Violations, m.BreakGlass, m.Duration)
	return m
}

// Handler serves /validate.
type Handler struct {
	Policy  *policy.Config
	Metrics *Metrics
	Log     *slog.Logger
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() { h.Metrics.Duration.Observe(time.Since(start).Seconds()) }()

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		http.Error(w, "expected application/json", http.StatusUnsupportedMediaType)
		return
	}
	var review admissionv1.AdmissionReview
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&review); err != nil {
		http.Error(w, "invalid AdmissionReview: "+err.Error(), http.StatusBadRequest)
		return
	}
	if review.Request == nil {
		http.Error(w, "AdmissionReview has no request", http.StatusBadRequest)
		return
	}

	resp := h.Review(review.Request)
	resp.UID = review.Request.UID
	out := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Response: resp,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		h.Log.Error("writing response", "err", err)
	}
}

// Review decides one admission request.
func (h *Handler) Review(req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	kind := req.Kind.Kind
	decide := func(decision string, resp *admissionv1.AdmissionResponse) *admissionv1.AdmissionResponse {
		h.Metrics.Requests.WithLabelValues(kind, string(req.Operation), decision).Inc()
		return resp
	}
	allow := &admissionv1.AdmissionResponse{Allowed: true}

	if req.Operation != admissionv1.Create && req.Operation != admissionv1.Update {
		return decide("allowed", allow)
	}
	if h.Policy.Exempt(req.Namespace) {
		return decide("exempt", allow)
	}

	meta, labels, spec, path, err := extract(req)
	if err != nil {
		// Fail closed on objects we claim to handle but cannot read.
		h.Log.Error("decoding object", "kind", kind, "namespace", req.Namespace, "name", req.Name, "err", err)
		return decide("error", &admissionv1.AdmissionResponse{Result: &metav1.Status{
			Status: metav1.StatusFailure, Code: http.StatusBadRequest, Reason: metav1.StatusReasonBadRequest,
			Message: fmt.Sprintf("guardrails: cannot decode %s: %v", kind, err),
		}})
	}
	if spec == nil {
		return decide("allowed", allow)
	}

	violations := h.Policy.Evaluate(labels, spec, path)
	if len(violations) == 0 {
		return decide("allowed", allow)
	}

	// Ratchet on UPDATE: a violation the object already had is reported but not enforced, so
	// workloads that predate a rule can still be scaled, relabelled or patched; only changes that
	// introduce a new violation are denied.
	var preexisting []string
	if req.Operation == admissionv1.Update && len(req.OldObject.Raw) > 0 {
		oldReq := *req
		oldReq.Object = req.OldObject
		if _, oldLabels, oldSpec, oldPath, err := extract(&oldReq); err == nil && oldSpec != nil {
			had := map[policy.Violation]bool{}
			for _, v := range h.Policy.Evaluate(oldLabels, oldSpec, oldPath) {
				had[v] = true
			}
			var fresh []policy.Violation
			for _, v := range violations {
				if had[v] {
					preexisting = append(preexisting, "guardrails: pre-existing, fix soon: "+v.String())
				} else {
					fresh = append(fresh, v)
				}
			}
			violations = fresh
		}
		if len(violations) == 0 {
			return decide("grandfathered", &admissionv1.AdmissionResponse{Allowed: true, Warnings: preexisting})
		}
	}
	for _, v := range violations {
		h.Metrics.Violations.WithLabelValues(v.Rule, req.Namespace).Inc()
	}
	name := meta.Name
	if name == "" {
		name = meta.GenerateName + "*"
	}
	msgs := make([]string, len(violations))
	for i, v := range violations {
		msgs[i] = v.String()
	}
	logAttrs := []any{"kind", kind, "namespace", req.Namespace, "name", name, "user", req.UserInfo.Username,
		"uid", req.UID, "dryRun", req.DryRun != nil && *req.DryRun, "violations", msgs}

	if ticket := strings.TrimSpace(meta.Annotations[policy.BreakGlassAnnotation]); ticket != "" && h.Policy.AllowBreakGlass {
		h.Metrics.BreakGlass.WithLabelValues(req.Namespace).Inc()
		h.Log.Warn("break-glass admission", append(logAttrs, "ticket", ticket)...)
		warnings := append([]string{fmt.Sprintf("guardrails: admitted by break-glass (%s); fix before the exception expires", ticket)}, msgs...)
		return decide("break-glass", &admissionv1.AdmissionResponse{Allowed: true, Warnings: warnings})
	}

	if h.Policy.Enforcement == policy.Warn {
		h.Log.Info("admitted with warnings", logAttrs...)
		return decide("warned", &admissionv1.AdmissionResponse{Allowed: true, Warnings: append(prefix(msgs), preexisting...)})
	}

	h.Log.Info("denied", logAttrs...)
	return decide("denied", &admissionv1.AdmissionResponse{
		Allowed: false,
		// The violations are in the message; repeating them as warnings would print them twice.
		Warnings: preexisting,
		Result: &metav1.Status{
			Status: metav1.StatusFailure, Code: http.StatusForbidden, Reason: metav1.StatusReasonForbidden,
			Message: fmt.Sprintf("guardrails: %s %q violates %d rule(s): %s", kind, name, len(violations), strings.Join(msgs, "; ")),
		},
	})
}

func prefix(msgs []string) []string {
	out := make([]string, len(msgs))
	for i, m := range msgs {
		out[i] = "guardrails: " + m
	}
	return out
}

// extract returns the object's metadata, the pod labels and spec to evaluate, and the field path
// of the spec. Kinds without a pod template return a nil spec.
func extract(req *admissionv1.AdmissionRequest) (metav1.ObjectMeta, map[string]string, *corev1.PodSpec, string, error) {
	raw := req.Object.Raw
	gk := req.Kind.Group + "/" + req.Kind.Kind
	tmpl := func(obj interface {
		GetObjectMeta() metav1.Object
	}, t *corev1.PodTemplateSpec) (metav1.ObjectMeta, map[string]string, *corev1.PodSpec, string, error) {
		m := obj.GetObjectMeta()
		// Break-glass is read from the pod template, not the workload: template annotations reach
		// the ReplicaSet/Job and the Pods, which are admitted again by this webhook.
		meta := metav1.ObjectMeta{Name: m.GetName(), GenerateName: m.GetGenerateName(), Annotations: t.Annotations}
		return meta, t.Labels, &t.Spec, "spec.template.spec", nil
	}
	switch gk {
	case "/Pod":
		var o corev1.Pod
		if err := json.Unmarshal(raw, &o); err != nil {
			return metav1.ObjectMeta{}, nil, nil, "", err
		}
		return o.ObjectMeta, o.Labels, &o.Spec, "spec", nil
	case "apps/Deployment":
		var o appsv1.Deployment
		if err := json.Unmarshal(raw, &o); err != nil {
			return metav1.ObjectMeta{}, nil, nil, "", err
		}
		return tmpl(&o, &o.Spec.Template)
	case "apps/StatefulSet":
		var o appsv1.StatefulSet
		if err := json.Unmarshal(raw, &o); err != nil {
			return metav1.ObjectMeta{}, nil, nil, "", err
		}
		return tmpl(&o, &o.Spec.Template)
	case "apps/DaemonSet":
		var o appsv1.DaemonSet
		if err := json.Unmarshal(raw, &o); err != nil {
			return metav1.ObjectMeta{}, nil, nil, "", err
		}
		return tmpl(&o, &o.Spec.Template)
	case "apps/ReplicaSet":
		var o appsv1.ReplicaSet
		if err := json.Unmarshal(raw, &o); err != nil {
			return metav1.ObjectMeta{}, nil, nil, "", err
		}
		return tmpl(&o, &o.Spec.Template)
	case "batch/Job":
		var o batchv1.Job
		if err := json.Unmarshal(raw, &o); err != nil {
			return metav1.ObjectMeta{}, nil, nil, "", err
		}
		return tmpl(&o, &o.Spec.Template)
	case "batch/CronJob":
		var o batchv1.CronJob
		if err := json.Unmarshal(raw, &o); err != nil {
			return metav1.ObjectMeta{}, nil, nil, "", err
		}
		meta, labels, spec, _, err := tmpl(&o, &o.Spec.JobTemplate.Spec.Template)
		return meta, labels, spec, "spec.jobTemplate.spec.template.spec", err
	}
	return metav1.ObjectMeta{}, nil, nil, "", nil
}
