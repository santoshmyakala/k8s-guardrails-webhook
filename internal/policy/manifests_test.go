package policy

import (
	"os"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/yaml"
)

// The webhook's own Deployment and shipped policy must satisfy the guardrails it enforces, even
// though its namespace is exempt. Image rules are skipped: kustomize sets the image at release.
func TestShippedManifestsFollowTheirOwnPolicy(t *testing.T) {
	pol, err := Load("../../deploy/base/policy.yaml")
	if err != nil {
		t.Fatalf("shipped policy: %v", err)
	}
	if pol.Enforcement != Deny || !pol.RequireDigest || !pol.RequireNonRoot || !pol.RequireResources {
		t.Fatalf("shipped policy should enforce every rule, got %+v", pol)
	}
	pol.AllowedRegistries, pol.RequireDigest = nil, false

	raw, err := os.ReadFile("../../deploy/base/deployment.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var d appsv1.Deployment
	if err := yaml.UnmarshalStrict([]byte(strings.Split(string(raw), "\n---\n")[0]), &d); err != nil {
		t.Fatal(err)
	}
	if vs := pol.Evaluate(d.Spec.Template.Labels, &d.Spec.Template.Spec, "spec.template.spec"); len(vs) != 0 {
		t.Fatalf("the webhook's own Deployment violates its policy: %v", vs)
	}
}

// The webhook configuration's namespaceSelector and the policy's exemptNamespaces are two layers
// of the same decision; they must not drift apart.
func TestExemptionsMatchTheWebhookConfiguration(t *testing.T) {
	pol, err := Load("../../deploy/base/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../deploy/base/webhook.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Webhooks []struct {
			NamespaceSelector struct {
				MatchExpressions []struct {
					Key, Operator string
					Values        []string
				} `json:"matchExpressions"`
			} `json:"namespaceSelector"`
		} `json:"webhooks"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	expr := cfg.Webhooks[0].NamespaceSelector.MatchExpressions[0]
	if expr.Operator != "NotIn" || strings.Join(expr.Values, ",") != strings.Join(pol.ExemptNamespaces, ",") {
		t.Fatalf("webhook excludes %v but policy exempts %v", expr.Values, pol.ExemptNamespaces)
	}
}
