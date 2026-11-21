#!/usr/bin/env bash
# End-to-end test against a real API server (kind): cert-manager issues the webhook certificate
# and injects the CA, then the API server must enforce the policy. Requests use server-side dry
# run, which runs every admission webhook but persists nothing, so no test image is ever pulled.
set -euo pipefail

CERT_MANAGER_VERSION=${CERT_MANAGER_VERSION:-v1.21.3}
DIGEST="@sha256:$(printf 'e2e' | sha256sum | cut -d' ' -f1)" # syntactically valid; never pulled
pass=0

ok() { pass=$((pass + 1)); echo "PASS  $*"; }
fail() { echo "FAIL  $*" >&2; exit 1; }

# workload <kind> <labels-json> <image> [pod-template-annotations-json] -> JSON on stdout
workload() {
  local kind=$1 labels=$2 image=$3 annotations=${4:-'{}'}
  local spec='{"securityContext":{"runAsNonRoot":true},"containers":[{"name":"app","image":"'"$image"'",
    "resources":{"requests":{"cpu":"50m","memory":"64Mi"},"limits":{"memory":"128Mi"}},
    "securityContext":{"allowPrivilegeEscalation":false}}]}'
  if [ "$kind" = Pod ]; then
    echo '{"apiVersion":"v1","kind":"Pod","metadata":{"generateName":"e2e-","labels":'"$labels"',"annotations":'"$annotations"'},"spec":'"$spec"'}'
  else
    echo '{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"generateName":"e2e-"},"spec":{"selector":{"matchLabels":'"$labels"'},
      "template":{"metadata":{"labels":'"$labels"',"annotations":'"$annotations"'},"spec":'"$spec"'}}}'
  fi
}

# admit <namespace> <json> -> kubectl output; sets $rc
admit() { set +e; out=$(echo "$2" | kubectl -n "$1" create --dry-run=server -f - 2>&1); rc=$?; set -e; }

GOOD='{"team":"orders","cost-center":"cc-1042"}'

echo "== install cert-manager $CERT_MANAGER_VERSION"
kubectl apply -f "https://github.com/cert-manager/cert-manager/releases/download/$CERT_MANAGER_VERSION/cert-manager.yaml" >/dev/null
kubectl -n cert-manager wait --for=condition=Available deployment --all --timeout=300s

echo "== deploy the webhook"
# cert-manager's own webhook can take a few seconds to serve after it reports Available.
for i in $(seq 30); do kubectl apply -k deploy/overlays/e2e >/dev/null 2>&1 && break; sleep 5; done
kubectl apply -k deploy/overlays/e2e
kubectl -n guardrails-system wait --for=condition=Ready certificate/guardrails-webhook --timeout=120s
kubectl -n guardrails-system rollout status deployment/guardrails-webhook --timeout=180s
for i in $(seq 60); do
  [ -n "$(kubectl get validatingwebhookconfiguration guardrails -o jsonpath='{.webhooks[0].clientConfig.caBundle}')" ] && break
  sleep 2
done
kubectl create namespace orders >/dev/null

# Wait until the API server reaches the webhook (endpoints and CA propagate asynchronously).
for i in $(seq 30); do admit orders "$(workload Deployment "$GOOD" "ghcr.io/example/orders$DIGEST")"; [ $rc -eq 0 ] && break; sleep 2; done

echo "== assertions"
admit orders "$(workload Deployment "$GOOD" "ghcr.io/example/orders$DIGEST")"
[ $rc -eq 0 ] && ok "compliant Deployment is admitted" || fail "compliant Deployment denied: $out"

admit orders '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"debug"},"spec":{"containers":[{"name":"sh","image":"busybox:latest"}]}}'
[ $rc -ne 0 ] && grep -q 'denied the request: guardrails: Pod "debug" violates' <<<"$out" \
  && grep -q image-digest <<<"$out" && grep -q image-registry <<<"$out" && grep -q run-as-non-root <<<"$out" \
  && ok "non-compliant Pod is denied with every reason" || fail "expected a denial: $out"

admit orders "$(workload Deployment '{"team":"orders"}' "ghcr.io/example/orders$DIGEST")"
[ $rc -ne 0 ] && grep -q '"cost-center" is required' <<<"$out" && ok "Deployment without cost-center is denied" || fail "$out"

admit orders "$(workload Deployment "$GOOD" "ghcr.io/example/orders:1.4.2")"
[ $rc -ne 0 ] && grep -q 'must be pinned by digest' <<<"$out" && ok "tag-pinned image is denied" || fail "$out"

admit orders "$(workload Deployment "$GOOD" "ghcr.io/example-evil/orders$DIGEST")"
[ $rc -ne 0 ] && grep -q 'not from an allowed registry' <<<"$out" && ok "look-alike registry path is denied" || fail "$out"

admit orders "$(workload Deployment "$GOOD" "ghcr.io/example/orders:hotfix" '{"guardrails.platform/break-glass":"INC-2041"}')"
[ $rc -eq 0 ] && grep -q 'Warning: guardrails: admitted by break-glass (INC-2041)' <<<"$out" \
  && ok "break-glass admits with a warning" || fail "$out"

admit kube-system '{"apiVersion":"v1","kind":"Pod","metadata":{"generateName":"e2e-"},"spec":{"containers":[{"name":"x","image":"busybox"}]}}'
[ $rc -eq 0 ] && ok "exempt namespace is not checked" || fail "$out"

echo "== metrics"
kubectl -n guardrails-system port-forward deployment/guardrails-webhook 19090:9090 >/dev/null 2>&1 &
pf=$!
trap 'kill $pf 2>/dev/null || true' EXIT
for i in $(seq 20); do curl -sf http://127.0.0.1:19090/metrics -o metrics.txt && break; sleep 1; done
grep -q 'guardrails_admission_requests_total{decision="denied",kind="Pod",operation="CREATE"}' metrics.txt \
  && grep -q 'guardrails_break_glass_total{namespace="orders"}' metrics.txt \
  && ok "decisions and break-glass are exported as metrics" || fail "metrics missing: $(grep ^guardrails_ metrics.txt)"
kill $pf

echo "== fail closed"
kubectl -n guardrails-system scale deployment/guardrails-webhook --replicas=0
kubectl -n guardrails-system wait --for=delete pod -l app.kubernetes.io/name=guardrails-webhook --timeout=120s
admit orders "$(workload Deployment "$GOOD" "ghcr.io/example/orders$DIGEST")"
[ $rc -ne 0 ] && grep -q 'failed calling webhook' <<<"$out" \
  && ok "with the webhook down, workloads are rejected (failurePolicy: Fail)" || fail "expected fail-closed: $out"
kubectl -n guardrails-system scale deployment/guardrails-webhook --replicas=2
kubectl -n guardrails-system rollout status deployment/guardrails-webhook --timeout=180s

echo "$pass checks passed"
