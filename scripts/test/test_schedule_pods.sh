#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_LOCAL_DIR="${REPO_LOCAL_DIR:-$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel 2>/dev/null || (cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd))}"
OUT_DIR="${OUT_DIR:-${REPO_LOCAL_DIR}/_serverless_out}"

export KUBECONFIG="${KUBECONFIG:-${OUT_DIR}/lambda-apiserver.kubeconfig}"
NS="${NS:-hello-test}"
POD_BASENAME="${POD_BASENAME:-spread-pod-test}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%d%H%M%S)}"
APP_LABEL="${APP_LABEL:-spread-pod-test}"
RUN_LABEL="${RUN_LABEL:-${POD_BASENAME}-${RUN_ID}}"
POD_COUNT="${POD_COUNT:-6}"
POD_RUN_SECONDS="${POD_RUN_SECONDS:-30}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-90s}"
CLEANUP="${CLEANUP:-true}"
POD_SELECTOR="app=${APP_LABEL},run=${RUN_LABEL}"

if ! [[ "${POD_COUNT}" =~ ^[1-9][0-9]*$ ]]; then
  echo "POD_COUNT must be a positive integer, got: ${POD_COUNT}" >&2
  exit 1
fi

if [[ "${CLEANUP}" != "true" && "${CLEANUP}" != "false" ]]; then
  echo "CLEANUP must be true or false, got: ${CLEANUP}" >&2
  exit 1
fi

kubectl create namespace "${NS}" --dry-run=client -o yaml | kubectl apply -f -

echo "[*] Creating ${POD_COUNT} pods directly in namespace ${NS}"
echo "[*] Selecting pods with: ${POD_SELECTOR}"

for i in $(seq 1 "${POD_COUNT}"); do
  POD_NAME="${POD_BASENAME}-${RUN_ID}-${i}"
  cat <<EOF | kubectl apply -n "${NS}" -f -
apiVersion: v1
kind: Pod
metadata:
  name: ${POD_NAME}
  labels:
    app: ${APP_LABEL}
    run: ${RUN_LABEL}
spec:
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
  affinity:
    podAntiAffinity:
      preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          topologyKey: kubernetes.io/hostname
          labelSelector:
            matchLabels:
              app: ${APP_LABEL}
              run: ${RUN_LABEL}
  containers:
  - name: hello
    image: busybox:1.36
    command:
    - /bin/sh
    - -c
    - |
      echo hello from ${POD_NAME}
      sleep ${POD_RUN_SECONDS}
    resources:
      requests:
        cpu: "100m"
        memory: "64Mi"
EOF
done

echo
echo "[*] Waiting for ${POD_COUNT} pods to be created..."
deadline=$((SECONDS + 120))
while true; do
  pod_count="$(kubectl -n "${NS}" get pods -l "${POD_SELECTOR}" -o jsonpath='{.items[*].metadata.name}' | wc -w | tr -d ' ')"
  if [[ "${pod_count}" -ge "${POD_COUNT}" ]]; then
    break
  fi
  if (( SECONDS >= deadline )); then
    echo "[!] Timed out waiting for pods to be created"
    break
  fi
  sleep 1
done

echo
echo "[*] Waiting for pods to be scheduled..."
kubectl -n "${NS}" wait --for=condition=PodScheduled pod -l "${POD_SELECTOR}" --timeout="${WAIT_TIMEOUT}"

echo
echo "[*] Waiting for pods to leave Pending..."
deadline=$((SECONDS + 120))
while true; do
  pending_count="$(kubectl -n "${NS}" get pods -l "${POD_SELECTOR}" -o jsonpath='{range .items[*]}{.status.phase}{"\n"}{end}' | awk '$1 == "Pending" {count++} END {print count + 0}')"
  if [[ "${pending_count}" -eq 0 ]]; then
    break
  fi
  if (( SECONDS >= deadline )); then
    echo "[!] Timed out waiting for pods to leave Pending"
    break
  fi
  sleep 1
done

echo
kubectl get nodes -o wide
echo
echo "[*] Pods for this run:"
kubectl -n "${NS}" get pods -l "${POD_SELECTOR}" -o wide
echo
kubectl -n "${NS}" logs -l "${POD_SELECTOR}" --tail=-1 || true

if [[ "${CLEANUP}" == "true" ]]; then
  echo
  echo "[*] Cleaning up pods for this run..."
  kubectl -n "${NS}" delete pods -l "${POD_SELECTOR}" --ignore-not-found=true
else
  echo
  echo "[*] Leaving pods in place. Clean them up with:"
  echo "kubectl -n ${NS} delete pods -l ${POD_SELECTOR}"
fi
