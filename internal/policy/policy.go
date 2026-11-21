// Package policy evaluates Kubernetes pod specs against platform guardrails: trusted, digest-pinned
// images; FinOps labels; resource requests and memory limits; and a non-root, unprivileged runtime.
package policy

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"sigs.k8s.io/yaml"
)

// Enforcement decides what happens to a request that violates the policy.
type Enforcement string

const (
	// Deny rejects the request.
	Deny Enforcement = "deny"
	// Warn admits the request and returns the violations as warnings (kubectl prints them).
	Warn Enforcement = "warn"
)

// BreakGlassAnnotation admits a non-compliant workload in an emergency. Its value must reference
// a change or incident ticket; every use is logged, counted and returned as a warning.
const BreakGlassAnnotation = "guardrails.platform/break-glass"

// Rule identifiers, used in messages and metrics.
const (
	RuleRegistry          = "image-registry"
	RuleDigest            = "image-digest"
	RuleLabels            = "required-labels"
	RuleResources         = "resources"
	RuleNonRoot           = "run-as-non-root"
	RulePrivileged        = "privileged"
	RulePrivilegeEscalate = "privilege-escalation"
	RuleHostNamespaces    = "host-namespaces"
)

// Config is the policy, loaded from YAML.
type Config struct {
	Enforcement Enforcement `json:"enforcement"`
	// Namespaces the policy does not apply to. The ValidatingWebhookConfiguration should exclude
	// them too; this is the second layer.
	ExemptNamespaces []string `json:"exemptNamespaces"`
	// Registry prefixes images must come from, e.g. "ghcr.io/acme" or
	// "123456789012.dkr.ecr.eu-west-1.amazonaws.com". Matched on whole path segments.
	AllowedRegistries []string `json:"allowedRegistries"`
	// Require images to be pinned by digest (name@sha256:…), so what was scanned and signed is
	// what runs.
	RequireDigest bool `json:"requireDigest"`
	// Labels every pod must carry with a non-empty value (cost allocation).
	RequiredLabels []string `json:"requiredLabels"`
	// Require CPU and memory requests and a memory limit on every container. CPU limits are
	// deliberately not required: they cause throttling without protecting the node.
	RequireResources bool `json:"requireResources"`
	// Require runAsNonRoot, no privileged containers, allowPrivilegeEscalation: false and no host
	// namespaces.
	RequireNonRoot bool `json:"requireNonRoot"`
	// Whether the break-glass annotation is honoured.
	AllowBreakGlass bool `json:"allowBreakGlass"`
}

// Violation is one broken rule.
type Violation struct {
	Rule    string `json:"rule"`
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (v Violation) String() string { return fmt.Sprintf("[%s] %s: %s", v.Rule, v.Field, v.Message) }

// Load reads and validates a policy file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse parses and validates a policy document. Unknown fields are rejected, so a typo cannot
// silently switch a rule off.
func Parse(data []byte) (*Config, error) {
	var c Config
	if err := yaml.UnmarshalStrict(data, &c); err != nil {
		return nil, fmt.Errorf("parsing policy: %w", err)
	}
	switch c.Enforcement {
	case "":
		c.Enforcement = Deny
	case Deny, Warn:
	default:
		return nil, fmt.Errorf("enforcement must be %q or %q, got %q", Deny, Warn, c.Enforcement)
	}
	for i, r := range c.AllowedRegistries {
		r = strings.TrimSuffix(strings.TrimSpace(r), "/")
		// A host, optional port and optional path: no scheme, tag, digest or whitespace.
		if r == "" || strings.Contains(r, "://") || strings.ContainsAny(r, "@ \t") {
			return nil, fmt.Errorf("allowedRegistries[%d] %q must look like host[:port][/path]", i, r)
		}
		c.AllowedRegistries[i] = r
	}
	return &c, nil
}

// Exempt reports whether a namespace is outside the policy.
func (c *Config) Exempt(namespace string) bool {
	return slices.Contains(c.ExemptNamespaces, namespace)
}

var digestRef = regexp.MustCompile(`@sha256:[a-f0-9]{64}$`)

// NormaliseImage expands a reference the way the container runtime does: "nginx" becomes
// "docker.io/library/nginx", and "acme/app" becomes "docker.io/acme/app".
func NormaliseImage(image string) string {
	first, rest, found := strings.Cut(image, "/")
	if !found {
		return "docker.io/library/" + image
	}
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return image
	}
	return "docker.io/" + first + "/" + rest
}

// registryAllowed matches whole path segments, so "ghcr.io/acme" allows "ghcr.io/acme/app" but
// not "ghcr.io/acme-evil/app".
func (c *Config) registryAllowed(image string) bool {
	repo := NormaliseImage(image)
	if i := strings.IndexAny(repo, "@"); i >= 0 {
		repo = repo[:i]
	}
	for _, prefix := range c.AllowedRegistries {
		if strings.HasPrefix(repo, prefix+"/") {
			return true
		}
	}
	return false
}

// Evaluate checks a pod's labels and spec. path is the field path of the spec in the admitted
// object, e.g. "spec.template.spec" for a Deployment.
func (c *Config) Evaluate(labels map[string]string, spec *corev1.PodSpec, path string) []Violation {
	var vs []Violation
	add := func(rule, field, format string, args ...any) {
		vs = append(vs, Violation{Rule: rule, Field: field, Message: fmt.Sprintf(format, args...)})
	}

	labelPath := strings.TrimSuffix(path, ".spec") + ".metadata.labels"
	if path == "spec" {
		labelPath = "metadata.labels"
	}
	for _, l := range c.RequiredLabels {
		if strings.TrimSpace(labels[l]) == "" {
			add(RuleLabels, labelPath, "label %q is required for cost allocation", l)
		}
	}

	if c.RequireNonRoot {
		if spec.HostNetwork || spec.HostPID || spec.HostIPC {
			add(RuleHostNamespaces, path, "hostNetwork, hostPID and hostIPC must be false")
		}
	}

	type ctr struct {
		c    *corev1.Container
		path string
	}
	var all []ctr
	for i := range spec.InitContainers {
		all = append(all, ctr{&spec.InitContainers[i], fmt.Sprintf("%s.initContainers[%d]", path, i)})
	}
	for i := range spec.Containers {
		all = append(all, ctr{&spec.Containers[i], fmt.Sprintf("%s.containers[%d]", path, i)})
	}

	podRunAsNonRoot, podRunAsUser := false, (*int64)(nil)
	if sc := spec.SecurityContext; sc != nil {
		podRunAsNonRoot = sc.RunAsNonRoot != nil && *sc.RunAsNonRoot
		podRunAsUser = sc.RunAsUser
	}

	for _, k := range all {
		name := fmt.Sprintf("%s (%s)", k.path, k.c.Name)

		if len(c.AllowedRegistries) > 0 && !c.registryAllowed(k.c.Image) {
			add(RuleRegistry, name, "image %q is not from an allowed registry (%s)", k.c.Image,
				strings.Join(c.AllowedRegistries, ", "))
		}
		if c.RequireDigest && !digestRef.MatchString(k.c.Image) {
			add(RuleDigest, name, "image %q must be pinned by digest (name@sha256:…)", k.c.Image)
		}

		if c.RequireResources {
			req, lim := k.c.Resources.Requests, k.c.Resources.Limits
			if isZero(req, corev1.ResourceCPU) {
				add(RuleResources, name, "resources.requests.cpu is required")
			}
			if isZero(req, corev1.ResourceMemory) {
				add(RuleResources, name, "resources.requests.memory is required")
			}
			if isZero(lim, corev1.ResourceMemory) {
				add(RuleResources, name, "resources.limits.memory is required")
			}
		}

		if c.RequireNonRoot {
			sc := k.c.SecurityContext
			nonRoot := podRunAsNonRoot
			runAsUser := podRunAsUser
			if sc != nil && sc.RunAsNonRoot != nil {
				nonRoot = *sc.RunAsNonRoot
			}
			if sc != nil && sc.RunAsUser != nil {
				runAsUser = sc.RunAsUser
			}
			if runAsUser != nil && *runAsUser == 0 {
				add(RuleNonRoot, name, "runAsUser must not be 0")
			} else if !nonRoot {
				add(RuleNonRoot, name, "securityContext.runAsNonRoot must be true (container or pod)")
			}
			if sc != nil && sc.Privileged != nil && *sc.Privileged {
				add(RulePrivileged, name, "privileged containers are not allowed")
			}
			if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
				add(RulePrivilegeEscalate, name, "securityContext.allowPrivilegeEscalation must be false")
			}
		}
	}
	return vs
}

func isZero(list corev1.ResourceList, name corev1.ResourceName) bool {
	q, ok := list[name]
	return !ok || q.Cmp(resource.Quantity{}) <= 0
}
