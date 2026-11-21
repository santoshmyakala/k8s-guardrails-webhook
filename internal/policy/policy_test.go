package policy

import (
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

const digest = "@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func testPolicy(t *testing.T) *Config {
	t.Helper()
	c, err := Parse([]byte(`
enforcement: deny
exemptNamespaces: [kube-system]
allowedRegistries: [ghcr.io/acme, "123456789012.dkr.ecr.eu-west-1.amazonaws.com/"]
requireDigest: true
requiredLabels: [team, cost-center]
requireResources: true
requireNonRoot: true
allowBreakGlass: true
`))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func ptr[T any](v T) *T { return &v }

// compliant returns labels and a spec that pass every rule; tests break one thing at a time.
func compliant() (map[string]string, *corev1.PodSpec) {
	return map[string]string{"team": "orders", "cost-center": "cc-1042"}, &corev1.PodSpec{
		SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: ptr(true)},
		Containers: []corev1.Container{{
			Name:  "app",
			Image: "ghcr.io/acme/orders" + digest,
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("128Mi")},
				Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")},
			},
			SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: ptr(false)},
		}},
	}
}

func rules(vs []Violation) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.Rule)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func TestCompliantPodPasses(t *testing.T) {
	labels, spec := compliant()
	if vs := testPolicy(t).Evaluate(labels, spec, "spec"); len(vs) != 0 {
		t.Fatalf("expected no violations, got %v", vs)
	}
}

func TestEachRuleCatchesItsViolation(t *testing.T) {
	cases := []struct {
		name   string
		break_ func(map[string]string, *corev1.PodSpec)
		want   []string
	}{
		{"untrusted registry", func(_ map[string]string, s *corev1.PodSpec) { s.Containers[0].Image = "docker.io/acme/orders" + digest }, []string{RuleRegistry}},
		{"look-alike registry path", func(_ map[string]string, s *corev1.PodSpec) {
			s.Containers[0].Image = "ghcr.io/acme-evil/orders" + digest
		}, []string{RuleRegistry}},
		{"Docker Hub short name", func(_ map[string]string, s *corev1.PodSpec) { s.Containers[0].Image = "nginx" + digest }, []string{RuleRegistry}},
		{"tag instead of digest", func(_ map[string]string, s *corev1.PodSpec) { s.Containers[0].Image = "ghcr.io/acme/orders:1.4.2" }, []string{RuleDigest}},
		{"tag and malformed digest", func(_ map[string]string, s *corev1.PodSpec) { s.Containers[0].Image = "ghcr.io/acme/orders@sha256:abc" }, []string{RuleDigest}},
		{"missing label", func(l map[string]string, _ *corev1.PodSpec) { delete(l, "cost-center") }, []string{RuleLabels}},
		{"blank label", func(l map[string]string, _ *corev1.PodSpec) { l["team"] = " " }, []string{RuleLabels}},
		{"no memory limit", func(_ map[string]string, s *corev1.PodSpec) {
			delete(s.Containers[0].Resources.Limits, corev1.ResourceMemory)
		}, []string{RuleResources}},
		{"zero cpu request", func(_ map[string]string, s *corev1.PodSpec) {
			s.Containers[0].Resources.Requests[corev1.ResourceCPU] = resource.MustParse("0")
		}, []string{RuleResources}},
		{"no runAsNonRoot anywhere", func(_ map[string]string, s *corev1.PodSpec) { s.SecurityContext = nil }, []string{RuleNonRoot}},
		{"container overrides pod to root", func(_ map[string]string, s *corev1.PodSpec) {
			s.Containers[0].SecurityContext.RunAsNonRoot = ptr(false)
		}, []string{RuleNonRoot}},
		{"runAsUser 0", func(_ map[string]string, s *corev1.PodSpec) {
			s.Containers[0].SecurityContext.RunAsUser = ptr(int64(0))
		}, []string{RuleNonRoot}},
		{"privileged", func(_ map[string]string, s *corev1.PodSpec) { s.Containers[0].SecurityContext.Privileged = ptr(true) }, []string{RulePrivileged}},
		{"privilege escalation unset", func(_ map[string]string, s *corev1.PodSpec) { s.Containers[0].SecurityContext = nil }, []string{RulePrivilegeEscalate}},
		{"host network", func(_ map[string]string, s *corev1.PodSpec) { s.HostNetwork = true }, []string{RuleHostNamespaces}},
		{"non-compliant init container", func(_ map[string]string, s *corev1.PodSpec) {
			s.InitContainers = []corev1.Container{{Name: "migrate", Image: "busybox:latest"}}
		}, []string{RuleDigest, RuleRegistry, RulePrivilegeEscalate, RuleResources}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			labels, spec := compliant()
			tc.break_(labels, spec)
			got := rules(testPolicy(t).Evaluate(labels, spec, "spec"))
			want := slices.Clone(tc.want)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("rules = %v, want %v", got, want)
			}
		})
	}
}

// Matches Pod Security "restricted": a non-zero runAsUser alone is not enough, because an image
// change or a removed field could silently fall back to root. runAsNonRoot makes the kubelet check.
func TestRunAsUserAloneIsNotEnough(t *testing.T) {
	labels, spec := compliant()
	spec.SecurityContext = &corev1.PodSecurityContext{RunAsUser: ptr(int64(65532))}
	if got := rules(testPolicy(t).Evaluate(labels, spec, "spec")); !slices.Equal(got, []string{RuleNonRoot}) {
		t.Fatalf("rules = %v, want [%s]", got, RuleNonRoot)
	}
	spec.SecurityContext.RunAsNonRoot = ptr(true)
	if vs := testPolicy(t).Evaluate(labels, spec, "spec"); len(vs) != 0 {
		t.Fatalf("expected no violations, got %v", vs)
	}
}

func TestFieldPathsPointAtTheTemplate(t *testing.T) {
	labels, spec := compliant()
	delete(labels, "team")
	spec.Containers[0].Image = "ghcr.io/acme/orders:latest"
	vs := testPolicy(t).Evaluate(labels, spec, "spec.template.spec")
	fields := []string{vs[0].Field, vs[1].Field}
	if fields[0] != "spec.template.metadata.labels" || fields[1] != "spec.template.spec.containers[0] (app)" {
		t.Fatalf("unexpected field paths %q", fields)
	}
}

func TestNormaliseImage(t *testing.T) {
	for in, want := range map[string]string{
		"nginx":                      "docker.io/library/nginx",
		"nginx:1.27":                 "docker.io/library/nginx:1.27",
		"acme/app":                   "docker.io/acme/app",
		"ghcr.io/acme/app":           "ghcr.io/acme/app",
		"localhost:5000/app":         "localhost:5000/app",
		"localhost/app":              "localhost/app",
		"registry.k8s.io/pause:3.10": "registry.k8s.io/pause:3.10",
	} {
		if got := NormaliseImage(in); got != want {
			t.Errorf("NormaliseImage(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseRejectsMistakes(t *testing.T) {
	for doc, want := range map[string]string{
		"enforcement: audit":                      "enforcement must be",
		"requireDigests: true":                    "unknown field",
		`allowedRegistries: ["https://ghcr.io"]`:  "must look like",
		`allowedRegistries: ["ghcr.io/a@sha256"]`: "must look like",
	} {
		if _, err := Parse([]byte(doc)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) error = %v, want %q", doc, err, want)
		}
	}
	c, err := Parse([]byte("requireDigest: true"))
	if err != nil || c.Enforcement != Deny {
		t.Fatalf("enforcement should default to deny, got %v %v", c, err)
	}
}
