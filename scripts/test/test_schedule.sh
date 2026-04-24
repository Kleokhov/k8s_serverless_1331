#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_LOCAL_DIR="${REPO_LOCAL_DIR:-$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel 2>/dev/null || (cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd))}"
OUT_DIR="${OUT_DIR:-${REPO_LOCAL_DIR}/_ec2_out}"

export KUBECONFIG="${KUBECONFIG:-${OUT_DIR}/admin.public.conf}"
NS="${NS:-hello-test}"
JOB_BASENAME="${JOB_BASENAME:-spread-test}"
JOB_NAME="${JOB_NAME:-${JOB_BASENAME}-$(date -u +%Y%m%d%H%M%S)}"
APP_LABEL="${APP_LABEL:-spread-test}"
RUN_LABEL="${RUN_LABEL:-${JOB_NAME}}"
COMPLETIONS="${COMPLETIONS:-6}"
PARALLELISM="${PARALLELISM:-${COMPLETIONS}}"
POD_RUN_SECONDS="${POD_RUN_SECONDS:-10}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-60s}"
JOB_TTL_SECONDS="${JOB_TTL_SECONDS:-30}"
POD_SELECTOR="app=${APP_LABEL},run=${RUN_LABEL}"

kubectl create namespace "${NS}" --dry-run=client -o yaml | kubectl apply -f -

echo "[*] Creating job ${JOB_NAME} in namespace ${NS}"
echo "[*] Selecting pods with: ${POD_SELECTOR}"

cat <<EOF | kubectl apply -n "${NS}" -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: ${JOB_NAME}
spec:
  completions: ${COMPLETIONS}
  parallelism: ${PARALLELISM}
  backoffLimit: 0
  ttlSecondsAfterFinished: ${JOB_TTL_SECONDS}
  template:
    metadata:
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
          echo hello world
          sleep ${POD_RUN_SECONDS}
        resources:
          requests:
            cpu: "100m"
            memory: "64Mi"
EOF

echo
echo "[*] Waiting for ${COMPLETIONS} pods to be created..."
deadline=$((SECONDS + 120))
while true; do
  pod_count="$(kubectl -n "${NS}" get pods -l "${POD_SELECTOR}" -o jsonpath='{.items[*].metadata.name}' | wc -w | tr -d ' ')"
  if [[ "${pod_count}" -ge "${COMPLETIONS}" ]]; then
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
echo "[*] Waiting for pods to start..."
kubectl -n "${NS}" wait --for=condition=Ready pod -l "${POD_SELECTOR}" --timeout="${WAIT_TIMEOUT}"

echo
echo "[*] Waiting for job to complete..."
kubectl -n "${NS}" wait --for=condition=complete "job/${JOB_NAME}" --timeout="${WAIT_TIMEOUT}"

echo
kubectl get nodes -o wide
echo
echo "[*] Pods for this run (completed Job pods show READY 0/1 after exit):"
kubectl -n "${NS}" get pods -l "${POD_SELECTOR}" -o wide
echo
kubectl -n "${NS}" logs -l "${POD_SELECTOR}" --tail=-1
echo
kubectl -n "${NS}" describe "job/${JOB_NAME}"
