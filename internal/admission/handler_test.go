package admission

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/santoshmyakala/k8s-guardrails-webhook/internal/policy"
)

const digest = "@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newHandler(t *testing.T, enforcement string) (*Handler, *httptest.Server) {
	t.Helper()
	pol, err := policy.Parse([]byte(`
enforcement: ` + enforcement + `
exemptNamespaces: [kube-system]
allowedRegistries: [ghcr.io/acme]
requireDigest: true
requiredLabels: [team, cost-center]
requireResources: true
requireNonRoot: true
allowBreakGlass: true
`))
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Policy: pol, Metrics: NewMetrics(prometheus.NewRegistry()), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return h, srv
}

// podTemplate is a pod template (metadata + spec) as JSON; image and labels are parameters.
func podTemplate(image, labels, annotations string) string {
	return `{"metadata":{"labels":` + labels + `,"annotations":` + annotations + `},
	"spec":{"securityContext":{"runAsNonRoot":true},"containers":[{"name":"app","image":"` + image + `",
	"resources":{"requests":{"cpu":"100m","memory":"128Mi"},"limits":{"memory":"256Mi"}},
	"securityContext":{"allowPrivilegeEscalation":false}}]}}`
}

const goodLabels = `{"team":"orders","cost-center":"cc-1042"}`

func deployment(tmpl string) string {
	return `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"orders"},"spec":{"selector":{},"template":` + tmpl + `}}`
}

func review(t *testing.T, srv *httptest.Server, group, kind, ns string, op admissionv1.Operation, object string) *admissionv1.AdmissionResponse {
	t.Helper()
	return reviewUpdate(t, srv, group, kind, ns, op, object, "")
}

func reviewUpdate(t *testing.T, srv *httptest.Server, group, kind, ns string, op admissionv1.Operation, object, old string) *admissionv1.AdmissionResponse {
	t.Helper()
	req := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:       types.UID("uid-42"),
			Kind:      metav1.GroupVersionKind{Group: group, Version: "v1", Kind: kind},
			Namespace: ns,
			Operation: op,
		},
	}
	req.Request.Object.Raw = []byte(object)
	if old != "" {
		req.Request.OldObject.Raw = []byte(old)
	}
	body, _ := json.Marshal(req)
	resp, err := http.Post(srv.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("HTTP %d: %s", resp.StatusCode, b)
	}
	var out admissionv1.AdmissionReview
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.APIVersion != "admission.k8s.io/v1" || out.Kind != "AdmissionReview" {
		t.Fatalf("response type meta = %v", out.TypeMeta)
	}
	if out.Response.UID != "uid-42" {
		t.Fatalf("response must echo the request UID, got %q", out.Response.UID)
	}
	return out.Response
}

func TestCompliantDeploymentIsAllowed(t *testing.T) {
	h, srv := newHandler(t, "deny")
	r := review(t, srv, "apps", "Deployment", "orders", admissionv1.Create, deployment(podTemplate("ghcr.io/acme/orders"+digest, goodLabels, `{}`)))
	if !r.Allowed || len(r.Warnings) != 0 {
		t.Fatalf("expected a clean allow, got %+v", r)
	}
	if got := testutil.ToFloat64(h.Metrics.Requests.WithLabelValues("Deployment", "CREATE", "allowed")); got != 1 {
		t.Fatalf("allowed counter = %v", got)
	}
}

func TestNonCompliantPodIsDeniedWithEveryReason(t *testing.T) {
	h, srv := newHandler(t, "deny")
	pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"debug","labels":{"team":"orders"}},
	"spec":{"containers":[{"name":"shell","image":"busybox:latest","securityContext":{"privileged":true}}]}}`
	r := review(t, srv, "", "Pod", "orders", admissionv1.Create, pod)
	if r.Allowed {
		t.Fatal("expected a denial")
	}
	if r.Result.Code != http.StatusForbidden {
		t.Fatalf("code = %d", r.Result.Code)
	}
	for _, want := range []string{`Pod "debug" violates`, policy.RuleRegistry, policy.RuleDigest, policy.RuleLabels, `"cost-center"`,
		policy.RuleResources, policy.RuleNonRoot, policy.RulePrivileged, policy.RulePrivilegeEscalate} {
		if !strings.Contains(r.Result.Message, want) {
			t.Errorf("message misses %q:\n%s", want, r.Result.Message)
		}
	}
	if got := testutil.ToFloat64(h.Metrics.Violations.WithLabelValues(policy.RulePrivileged, "orders")); got != 1 {
		t.Fatalf("violation counter = %v", got)
	}
}

func TestWarnModeAdmitsWithWarnings(t *testing.T) {
	_, srv := newHandler(t, "warn")
	r := review(t, srv, "apps", "Deployment", "orders", admissionv1.Create, deployment(podTemplate("ghcr.io/acme/orders:1.0", goodLabels, `{}`)))
	if !r.Allowed || len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], policy.RuleDigest) {
		t.Fatalf("expected allow with one digest warning, got %+v", r)
	}
}

func TestBreakGlassOnThePodTemplate(t *testing.T) {
	h, srv := newHandler(t, "deny")
	tmpl := podTemplate("ghcr.io/acme/orders:hotfix", goodLabels, `{"`+policy.BreakGlassAnnotation+`":"INC-2041"}`)
	r := review(t, srv, "apps", "Deployment", "orders", admissionv1.Create, deployment(tmpl))
	if !r.Allowed || !strings.Contains(r.Warnings[0], "INC-2041") {
		t.Fatalf("expected a break-glass allow citing the ticket, got %+v", r)
	}
	// The Pods the Deployment creates carry the template annotations, so they are admitted too.
	pod := strings.Replace(tmpl, `{"metadata":{`, `{"apiVersion":"v1","kind":"Pod","metadata":{"generateName":"orders-",`, 1)
	if r := review(t, srv, "", "Pod", "orders", admissionv1.Create, pod); !r.Allowed {
		t.Fatalf("pod from a break-glass template was denied: %+v", r.Result)
	}
	if got := testutil.ToFloat64(h.Metrics.BreakGlass.WithLabelValues("orders")); got != 2 {
		t.Fatalf("break-glass counter = %v", got)
	}
}

func TestBreakGlassOnTheWorkloadOnlyIsIgnored(t *testing.T) {
	_, srv := newHandler(t, "deny")
	obj := strings.Replace(deployment(podTemplate("ghcr.io/acme/orders:hotfix", goodLabels, `{}`)),
		`"metadata":{"name":"orders"}`, `"metadata":{"name":"orders","annotations":{"`+policy.BreakGlassAnnotation+`":"INC-1"}}`, 1)
	if r := review(t, srv, "apps", "Deployment", "orders", admissionv1.Create, obj); r.Allowed {
		t.Fatal("break-glass on the Deployment would not reach its Pods, so it must not admit the Deployment")
	}
}

func TestCronJobUsesTheJobTemplatePath(t *testing.T) {
	_, srv := newHandler(t, "deny")
	cron := `{"apiVersion":"batch/v1","kind":"CronJob","metadata":{"name":"nightly"},"spec":{"schedule":"0 2 * * *",
	"jobTemplate":{"spec":{"template":` + podTemplate("ghcr.io/acme/report"+digest, `{"team":"orders"}`, `{}`) + `}}}}`
	r := review(t, srv, "batch", "CronJob", "orders", admissionv1.Create, cron)
	if r.Allowed || !strings.Contains(r.Result.Message, "spec.jobTemplate.spec.template.metadata.labels") {
		t.Fatalf("expected a label denial on the job template, got %+v", r.Result)
	}
}

func TestPassThroughCases(t *testing.T) {
	_, srv := newHandler(t, "deny")
	bad := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"x"},"spec":{"containers":[{"name":"x","image":"busybox"}]}}`
	for name, r := range map[string]*admissionv1.AdmissionResponse{
		"exempt namespace": review(t, srv, "", "Pod", "kube-system", admissionv1.Create, bad),
		"delete":           review(t, srv, "", "Pod", "orders", admissionv1.Delete, `null`),
		"kind without pods": review(t, srv, "", "ConfigMap", "orders", admissionv1.Create,
			`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"c"}}`),
	} {
		if !r.Allowed {
			t.Errorf("%s: expected allow, got %+v", name, r.Result)
		}
	}
}

func TestUndecodableObjectFailsClosed(t *testing.T) {
	_, srv := newHandler(t, "deny")
	r := review(t, srv, "apps", "Deployment", "orders", admissionv1.Create, `{"spec":{"replicas":"three"}}`)
	if r.Allowed || r.Result.Code != http.StatusBadRequest {
		t.Fatalf("expected a 400 denial, got %+v", r)
	}
}

func TestBadHTTPRequests(t *testing.T) {
	_, srv := newHandler(t, "deny")
	for name, tc := range map[string]struct {
		method, ctype, body string
		want                int
	}{
		"GET":              {http.MethodGet, "", "", http.StatusMethodNotAllowed},
		"wrong media type": {http.MethodPost, "text/plain", "{}", http.StatusUnsupportedMediaType},
		"not JSON":         {http.MethodPost, "application/json", "{", http.StatusBadRequest},
		"no request":       {http.MethodPost, "application/json", `{"kind":"AdmissionReview"}`, http.StatusBadRequest},
		"oversized body":   {http.MethodPost, "application/json", `{"x":"` + strings.Repeat("a", maxBodyBytes) + `"}`, http.StatusBadRequest},
	} {
		req, _ := http.NewRequest(tc.method, srv.URL, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", tc.ctype)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("%s: HTTP %d, want %d", name, resp.StatusCode, tc.want)
		}
	}
}

func TestUpdatesRatchet(t *testing.T) {
	h, srv := newHandler(t, "deny")
	// A Deployment from before the digest rule: tag-pinned.
	legacy := deployment(podTemplate("ghcr.io/acme/orders:1.0", goodLabels, `{}`))
	relabelled := deployment(podTemplate("ghcr.io/acme/orders:1.0", `{"team":"orders","cost-center":"cc-1042","tier":"web"}`, `{}`))

	r := reviewUpdate(t, srv, "apps", "Deployment", "orders", admissionv1.Update, relabelled, legacy)
	if !r.Allowed || len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "pre-existing") {
		t.Fatalf("an unrelated change to a legacy workload should be admitted with a warning, got %+v", r)
	}

	// Introducing a new violation in the same update is still denied.
	worse := deployment(podTemplate("ghcr.io/acme/orders:1.0", `{"team":"orders"}`, `{}`))
	r = reviewUpdate(t, srv, "apps", "Deployment", "orders", admissionv1.Update, worse, legacy)
	if r.Allowed || !strings.Contains(r.Result.Message, policy.RuleLabels) || strings.Contains(r.Result.Message, policy.RuleDigest) {
		t.Fatalf("only the new label violation should be denied, got %+v", r.Result)
	}
	if got := testutil.ToFloat64(h.Metrics.Requests.WithLabelValues("Deployment", "UPDATE", "grandfathered")); got != 1 {
		t.Fatalf("grandfathered counter = %v", got)
	}
}
