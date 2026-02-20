#!/usr/bin/env bash
set -euo pipefail

CTX="${CTX:-kind-local-apiserver}"
NS="podcrud-$(date +%s)"
POD="p1"

IMAGE1="${IMAGE1:-registry.k8s.io/pause:3.9}"
IMAGE2="${IMAGE2:-registry.k8s.io/pause:3.10}"

echo "==> Create namespace"
kubectl --context "$CTX" create namespace "$NS"

echo "==> Ensure default ServiceAccount exists (controller-manager would normally do this)"
kubectl --context "$CTX" -n "$NS" create serviceaccount default \
  --dry-run=client -o yaml | kubectl --context "$CTX" apply -f -

echo "==> Create pod (API object only)"
cat <<EOF | kubectl --context "$CTX" -n "$NS" create -f -
apiVersion: v1
kind: Pod
metadata:
  name: ${POD}
  labels:
    app: crud
spec:
  serviceAccountName: default
  automountServiceAccountToken: false
  restartPolicy: Never
  containers:
  - name: main
    image: ${IMAGE1}
    command: ["sh","-c","echo hello && sleep 3600"]
EOF

echo "==> Get pod (read back)"
kubectl --context "$CTX" -n "$NS" get pod "$POD" -o yaml

echo "==> Patch metadata label"
kubectl --context "$CTX" -n "$NS" patch pod "$POD" --type merge -p \
  '{"metadata":{"labels":{"patched":"true"}}}'
kubectl --context "$CTX" -n "$NS" get pod "$POD" -o jsonpath='{.metadata.labels.patched}{"\n"}'

echo "==> Patch image (allowed for Pods in many cases; if rejected, that's still useful signal)"
set +e
kubectl --context "$CTX" -n "$NS" patch pod "$POD" --type strategic -p \
  "{\"spec\":{\"containers\":[{\"name\":\"main\",\"image\":\"${IMAGE2}\"}]}}"
RC=$?
set -e
if [[ $RC -ne 0 ]]; then
  echo "NOTE: image patch rejected by validation; continuing."
fi

echo "==> Get pod again"
kubectl --context "$CTX" -n "$NS" get pod "$POD" -o jsonpath='{.spec.containers[0].image}{"\n"}'

echo "==> Delete pod (avoid kubectl wait/watch)"
kubectl --context "$CTX" -n "$NS" delete pod "$POD" --wait=false

echo "==> Confirm pod deleted (GET should fail)"
if kubectl --context "$CTX" -n "$NS" get pod "$POD" >/dev/null 2>&1; then
  echo "ERROR: pod still exists"
  exit 1
else
  echo "OK: pod not found"
fi

echo "==> Delete namespace (avoid kubectl wait/watch)"
kubectl --context "$CTX" delete namespace "$NS" --wait=false

echo "OK"