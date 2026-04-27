#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_LOCAL_DIR="${REPO_LOCAL_DIR:-$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel 2>/dev/null || (cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd))}"
OUT_DIR="${OUT_DIR:-${REPO_LOCAL_DIR}/_serverless_out}"
EC2_OUT_DIR="${EC2_OUT_DIR:-${REPO_LOCAL_DIR}/_ec2_out}"

POD_COUNT=""
TARGET=""
MODE="pods"
WORKLOAD_SLEEP_SECONDS="10"
NS="latency-test"
LABEL=""
RESULTS_DIR="${OUT_DIR}/latency_results"
WAIT_TIMEOUT_SECONDS="900"
POLL_INTERVAL_SECONDS="2"
CLEANUP="true"
POD_CPU_REQUEST="100m"
POD_MEMORY_REQUEST="64Mi"
IMAGE="busybox:1.36"
IMAGE_PULL_POLICY="IfNotPresent"
PYTHON_BIN="${PYTHON_BIN:-python3}"
HELPER_SCRIPT="${SCRIPT_DIR}/latency_metrics.py"
KUBECTL_APPLY_ATTEMPTS="${KUBECTL_APPLY_ATTEMPTS:-8}"

usage() {
  cat <<'EOF_USAGE'
Usage: ./scripts/test/test_latency.sh --count N [options]

Measures scheduling, node-pickup, and submit-to-start latency + throughput for a batch of N pods
against either a regular EC2 Kubernetes cluster or the serverless pipeline,
using the same workload shape for both so the numbers are directly comparable.

How it measures:
  - Submits N bare Pods (or one Job with parallelism=N completions=N) into a
    single namespace, in one apply burst.
  - Each pod runs a trivial workload (sleep WORKLOAD_SLEEP_SECONDS) so the
    submit-to-start number reflects pipeline overhead, not workload time.
  - Polls until every pod starts running (or fails before start) or
    WAIT_TIMEOUT_SECONDS elapses.
  - Snapshots `kubectl get pods -o json` and hands it to latency_metrics.py,
    which derives per-pod latencies from Pod conditions and container states
    and reports compact aggregates (avg, min, max) plus throughput.

Required:
  --count N                Number of pods to schedule (e.g. 10, 50, 100, 500).

Common options:
  --target serverless|serverful
                           Selects kubeconfig:
                             serverless -> $OUT_DIR/lambda-apiserver.kubeconfig
                             serverful  -> $EC2_OUT_DIR/admin.public.conf
                                           (the EC2 cluster from setup_ec2.sh)
                           Ignored if KUBECONFIG is already exported.
  --mode pods|job          pods (default): one Pod per workload unit, all
                           created in a single apply burst. job: a single Job
                           with parallelism=N completions=N.
  --workload-sleep S       Per-pod sleep, default 10s. This is excluded from
                           submit-to-start latency.
                           For large serverless batches, choose a value longer
                           than the expected submit-to-start window so PodGC
                           does not delete completed pods before observation.
  --namespace NS           Namespace to use, default 'latency-test'.
  --label NAME             Label written into the result JSON, e.g.
                           'serverless' or 'serverful-c5large'. Defaults to
                           the value of --target, else 'unknown'.
  --results-dir DIR        Where to write the JSON result file.
                           Default: $OUT_DIR/latency_results
  --timeout SECONDS        How long to wait for all pods to start.
                           Default 900s.
  --no-cleanup             Leave pods/job in place after the run.
  --cpu / --memory         Per-pod requests, defaults 100m / 64Mi.

Environment:
  KUBECTL_APPLY_ATTEMPTS   Retries for transient DynamoDB transaction
                           contention during the initial apply. Default 8.

Output:
  Writes <results-dir>/<label>_<mode>_n<N>_<run_id>.json with all per-pod
  timestamps and aggregates, and prints a human summary table to stdout.

Examples:
  # Serverless, 100 pods
  ./scripts/test/test_latency.sh --count 100 --target serverless

  # EC2 cluster, sweep across sizes
  for n in 10 50 100 500; do
    ./scripts/test/test_latency.sh --count "$n" --target serverful
  done

  # Compare via Job mode
  ./scripts/test/test_latency.sh --count 50 --mode job --target serverless
EOF_USAGE
}

while (( $# > 0 )); do
  case "$1" in
    --count)         POD_COUNT="$2"; shift 2 ;;
    --target)        TARGET="$2"; shift 2 ;;
    --mode)          MODE="$2"; shift 2 ;;
    --workload-sleep) WORKLOAD_SLEEP_SECONDS="$2"; shift 2 ;;
    --namespace)     NS="$2"; shift 2 ;;
    --label)         LABEL="$2"; shift 2 ;;
    --results-dir)   RESULTS_DIR="$2"; shift 2 ;;
    --timeout)       WAIT_TIMEOUT_SECONDS="$2"; shift 2 ;;
    --no-cleanup)    CLEANUP="false"; shift ;;
    --cpu)           POD_CPU_REQUEST="$2"; shift 2 ;;
    --memory)        POD_MEMORY_REQUEST="$2"; shift 2 ;;
    --image)         IMAGE="$2"; shift 2 ;;
    -h|--help)       usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "${POD_COUNT}" ]]; then
  echo "--count is required" >&2
  usage >&2
  exit 2
fi
if ! [[ "${POD_COUNT}" =~ ^[1-9][0-9]*$ ]]; then
  echo "--count must be a positive integer, got: ${POD_COUNT}" >&2
  exit 2
fi
if [[ "${MODE}" != "pods" && "${MODE}" != "job" ]]; then
  echo "--mode must be 'pods' or 'job', got: ${MODE}" >&2
  exit 2
fi
if ! [[ "${WAIT_TIMEOUT_SECONDS}" =~ ^[1-9][0-9]*$ ]]; then
  echo "--timeout must be a positive integer, got: ${WAIT_TIMEOUT_SECONDS}" >&2
  exit 2
fi
if ! [[ "${KUBECTL_APPLY_ATTEMPTS}" =~ ^[1-9][0-9]*$ ]]; then
  echo "KUBECTL_APPLY_ATTEMPTS must be a positive integer, got: ${KUBECTL_APPLY_ATTEMPTS}" >&2
  exit 2
fi

if [[ -z "${KUBECONFIG:-}" ]]; then
  case "${TARGET}" in
    serverless)
      export KUBECONFIG="${OUT_DIR}/lambda-apiserver.kubeconfig" ;;
    serverful)
      export KUBECONFIG="${EC2_OUT_DIR}/admin.public.conf" ;;
    "")
      export KUBECONFIG="${OUT_DIR}/lambda-apiserver.kubeconfig"
      TARGET="serverless" ;;
    *)
      echo "--target must be 'serverless' or 'serverful', got: ${TARGET}" >&2
      exit 2 ;;
  esac
fi

if [[ ! -f "${KUBECONFIG}" ]]; then
  echo "Kubeconfig not found: ${KUBECONFIG}" >&2
  echo "Either export KUBECONFIG or pass --target serverless|serverful" >&2
  exit 1
fi

if [[ -z "${LABEL}" ]]; then
  LABEL="${TARGET:-unknown}"
fi

if [[ ! -x "$(command -v kubectl)" ]]; then
  echo "kubectl not found in PATH" >&2
  exit 1
fi
if [[ ! -f "${HELPER_SCRIPT}" ]]; then
  echo "Helper script missing: ${HELPER_SCRIPT}" >&2
  exit 1
fi

mkdir -p "${RESULTS_DIR}"

RUN_ID="$(date -u +%Y%m%d%H%M%S)"
SAFE_LABEL="$(printf '%s' "${LABEL}" | tr -c 'a-zA-Z0-9._-' '-' | tr '[:upper:]' '[:lower:]')"
RUN_LABEL="latency-${SAFE_LABEL}-${RUN_ID}"
APP_LABEL="latency-test"
SELECTOR="app=${APP_LABEL},run=${RUN_LABEL}"
RESULT_FILE="${RESULTS_DIR}/${SAFE_LABEL}_${MODE}_n${POD_COUNT}_${RUN_ID}.json"

echo "[*] Target:           ${TARGET:-(KUBECONFIG override)}"
echo "[*] Kubeconfig:       ${KUBECONFIG}"
echo "[*] Namespace:        ${NS}"
echo "[*] Pod count:        ${POD_COUNT}"
echo "[*] Mode:             ${MODE}"
echo "[*] Workload sleep:   ${WORKLOAD_SLEEP_SECONDS}s"
echo "[*] Run label:        ${RUN_LABEL}"
echo "[*] Result file:      ${RESULT_FILE}"

kubectl create namespace "${NS}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

render_pod_manifest() {
  local pod_index="$1"
  local pod_name="$2"
  cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${pod_name}
  labels:
    app: ${APP_LABEL}
    run: ${RUN_LABEL}
    pod-index: "${pod_index}"
spec:
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
  containers:
  - name: worker
    image: ${IMAGE}
    imagePullPolicy: ${IMAGE_PULL_POLICY}
    command: ["/bin/sh", "-c", "sleep ${WORKLOAD_SLEEP_SECONDS}"]
    resources:
      requests:
        cpu: "${POD_CPU_REQUEST}"
        memory: "${POD_MEMORY_REQUEST}"
EOF
}

render_job_manifest() {
  cat <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: ${RUN_LABEL}
  labels:
    app: ${APP_LABEL}
    run: ${RUN_LABEL}
spec:
  completions: ${POD_COUNT}
  parallelism: ${POD_COUNT}
  backoffLimit: 0
  ttlSecondsAfterFinished: 600
  template:
    metadata:
      labels:
        app: ${APP_LABEL}
        run: ${RUN_LABEL}
    spec:
      restartPolicy: Never
      terminationGracePeriodSeconds: 0
      containers:
      - name: worker
        image: ${IMAGE}
        imagePullPolicy: ${IMAGE_PULL_POLICY}
        command: ["/bin/sh", "-c", "sleep ${WORKLOAD_SLEEP_SECONDS}"]
        resources:
          requests:
            cpu: "${POD_CPU_REQUEST}"
            memory: "${POD_MEMORY_REQUEST}"
EOF
}

build_manifest() {
  if [[ "${MODE}" == "job" ]]; then
    render_job_manifest
    return
  fi
  local first=1
  local i pod_name
  for ((i = 1; i <= POD_COUNT; i++)); do
    pod_name="$(printf 'lat-%s-%05d' "${RUN_ID}" "${i}")"
    if (( first )); then
      first=0
    else
      echo "---"
    fi
    render_pod_manifest "${i}" "${pod_name}"
  done
}

kubectl_apply_manifest() {
  local manifest_file="$1"
  local attempt output status sleep_seconds

  for ((attempt = 1; attempt <= KUBECTL_APPLY_ATTEMPTS; attempt++)); do
    if output="$(kubectl -n "${NS}" apply -f "${manifest_file}" 2>&1)"; then
      return 0
    else
      status=$?
    fi
    printf '%s\n' "${output}" >&2

    case "${output}" in
      *TransactionConflict*|*TransactionCanceledException*|*TransactWriteItems*) ;;
      *) return "${status}" ;;
    esac

    if (( attempt >= KUBECTL_APPLY_ATTEMPTS )); then
      echo "[!] kubectl apply still failed after ${KUBECTL_APPLY_ATTEMPTS} attempts" >&2
      return "${status}"
    fi

    sleep_seconds="${attempt}"
    if (( sleep_seconds > 5 )); then
      sleep_seconds=5
    fi
    echo "[!] kubectl apply hit transient DynamoDB transaction contention; retrying in ${sleep_seconds}s (attempt ${attempt}/${KUBECTL_APPLY_ATTEMPTS})" >&2
    sleep "${sleep_seconds}"
  done
}

phase_count_value() {
  local counts="$1"
  local key="$2"
  awk -v key="${key}" '
    {
      for (i = 1; i <= NF; i++) {
        split($i, kv, "=")
        if (kv[1] == key) {
          print kv[2]
          exit
        }
      }
    }
  ' <<< "${counts}"
}

pod_phase_counts_from_file() {
  local pods_json_file="$1"
  "${PYTHON_BIN}" -c '
import json
import sys

try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except (OSError, json.JSONDecodeError):
    print("total=0 pending=0 running=0 succeeded=0 failed=0 unknown=0")
    raise SystemExit(0)

counts = {}
total = 0
for pod in data.get("items") or []:
    phase = ((pod.get("status") or {}).get("phase")) or "Unknown"
    counts[phase] = counts.get(phase, 0) + 1
    total += 1

print(
    f"total={total} pending={counts.get('Pending', 0)} "
    f"running={counts.get('Running', 0)} succeeded={counts.get('Succeeded', 0)} "
    f"failed={counts.get('Failed', 0)} unknown={counts.get('Unknown', 0)}"
)
' "${pods_json_file}"
}

pod_start_counts_from_file() {
  local pods_json_file="$1"
  "${PYTHON_BIN}" -c '
import json
import sys

try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except (OSError, json.JSONDecodeError):
    print("started=0 start_or_failed=0")
    raise SystemExit(0)

started = 0
start_or_failed = 0
for pod in data.get("items") or []:
    status = pod.get("status") or {}
    phase = status.get("phase")
    has_started = False
    for container_status in status.get("containerStatuses") or []:
        state = container_status.get("state") or {}
        last_state = container_status.get("lastState") or {}
        running = state.get("running") or {}
        terminated = state.get("terminated") or {}
        last_terminated = last_state.get("terminated") or {}
        if running.get("startedAt") or terminated.get("startedAt") or last_terminated.get("startedAt"):
            has_started = True
            break

    if has_started:
        started += 1
        start_or_failed += 1
    elif phase == "Failed":
        start_or_failed += 1

print(f"started={started} start_or_failed={start_or_failed}")
' "${pods_json_file}"
}

merge_pod_snapshot() {
  local accumulated_file="$1"
  local current_file="$2"
  "${PYTHON_BIN}" -c '
import json
import os
import sys

accumulated_path, current_path = sys.argv[1:3]

def read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"items": []}

accumulated = read_json(accumulated_path)
current = read_json(current_path)

items = {}
order = []
for pod in (accumulated.get("items") or []):
    meta = pod.get("metadata") or {}
    key = meta.get("uid") or f"{meta.get('namespace', '')}/{meta.get('name', '')}"
    if not key:
        continue
    if key not in items:
        order.append(key)
    items[key] = pod

for pod in (current.get("items") or []):
    meta = pod.get("metadata") or {}
    key = meta.get("uid") or f"{meta.get('namespace', '')}/{meta.get('name', '')}"
    if not key:
        continue
    if key not in items:
        order.append(key)
    items[key] = pod

merged = {"apiVersion": current.get("apiVersion") or accumulated.get("apiVersion") or "v1",
          "kind": current.get("kind") or accumulated.get("kind") or "PodList",
          "items": [items[key] for key in order]}
tmp_path = accumulated_path + ".tmp"
with open(tmp_path, "w") as f:
    json.dump(merged, f)
os.replace(tmp_path, accumulated_path)
' "${accumulated_file}" "${current_file}"
}

MANIFEST_FILE="$(mktemp)"
CURRENT_PODS_JSON_FILE="$(mktemp)"
PODS_JSON_FILE="$(mktemp)"
printf '{"apiVersion":"v1","kind":"PodList","items":[]}\n' > "${PODS_JSON_FILE}"
trap 'rm -f "${MANIFEST_FILE}" "${CURRENT_PODS_JSON_FILE}" "${PODS_JSON_FILE}" "${EVENTS_JSON_FILE:-}"' EXIT
build_manifest > "${MANIFEST_FILE}"

SUBMIT_START_ISO="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
SUBMIT_START_EPOCH="$(date +%s)"
echo "[*] Submitting at ${SUBMIT_START_ISO}"

kubectl_apply_manifest "${MANIFEST_FILE}"

SUBMIT_END_ISO="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
SUBMIT_END_EPOCH="$(date +%s)"
echo "[*] Submitted in $((SUBMIT_END_EPOCH - SUBMIT_START_EPOCH))s, polling for pod start (timeout ${WAIT_TIMEOUT_SECONDS}s)"

deadline=$((SUBMIT_END_EPOCH + WAIT_TIMEOUT_SECONDS))
last_status_print=0
empty_after_seen_polls=0
while :; do
  now=$(date +%s)
  if (( now >= deadline )); then
    echo "[!] Timed out waiting for pods to start; capturing whatever state we have"
    break
  fi

  if ! kubectl -n "${NS}" get pods -l "${SELECTOR}" -o json > "${CURRENT_PODS_JSON_FILE}" 2>/dev/null; then
    printf '{"apiVersion":"v1","kind":"PodList","items":[]}\n' > "${CURRENT_PODS_JSON_FILE}"
  fi
  merge_pod_snapshot "${PODS_JSON_FILE}" "${CURRENT_PODS_JSON_FILE}"

  phase_counts="$(pod_phase_counts_from_file "${CURRENT_PODS_JSON_FILE}")"
  total="$(phase_count_value "${phase_counts}" total)"
  succeeded="$(phase_count_value "${phase_counts}" succeeded)"
  failed="$(phase_count_value "${phase_counts}" failed)"
  start_counts="$(pod_start_counts_from_file "${CURRENT_PODS_JSON_FILE}")"
  started="$(phase_count_value "${start_counts}" started)"
  start_or_failed="$(phase_count_value "${start_counts}" start_or_failed)"
  observed_phase_counts="$(pod_phase_counts_from_file "${PODS_JSON_FILE}")"
  observed_total="$(phase_count_value "${observed_phase_counts}" total)"
  observed_start_counts="$(pod_start_counts_from_file "${PODS_JSON_FILE}")"
  observed_started="$(phase_count_value "${observed_start_counts}" started)"
  observed_start_or_failed="$(phase_count_value "${observed_start_counts}" start_or_failed)"
  total="${total:-0}"
  succeeded="${succeeded:-0}"
  failed="${failed:-0}"
  started="${started:-0}"
  start_or_failed="${start_or_failed:-0}"
  observed_total="${observed_total:-0}"
  observed_started="${observed_started:-0}"
  observed_start_or_failed="${observed_start_or_failed:-0}"
  terminal=$(( succeeded + failed ))

  if (( total == 0 && observed_total > 0 )); then
    empty_after_seen_polls=$((empty_after_seen_polls + 1))
  else
    empty_after_seen_polls=0
  fi

  if (( now - last_status_print >= 5 )); then
    echo "[*] $(date -u '+%H:%M:%SZ') current ${phase_counts} started=${started}/${POD_COUNT} terminal=${terminal}/${POD_COUNT} observed=${observed_total}/${POD_COUNT} observed_started=${observed_started}/${POD_COUNT}"
    last_status_print="${now}"
  fi

  if (( observed_total >= POD_COUNT && observed_start_or_failed >= POD_COUNT )); then
    if (( observed_started >= POD_COUNT )); then
      echo "[*] All ${POD_COUNT} pods started"
    else
      echo "[*] All ${POD_COUNT} pods started or failed before start"
    fi
    break
  fi

  if (( empty_after_seen_polls >= 3 )); then
    echo "[!] All currently visible pods disappeared before ${POD_COUNT} pods were observed; continuing would wait until timeout."
    echo "[!] Capturing cumulative pod snapshots observed so far (${observed_total}/${POD_COUNT}). The serverless PodGC likely deleted completed pods during the run."
    break
  fi

  sleep "${POLL_INTERVAL_SECONDS}"
done

FINISH_ISO="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

EVENTS_JSON_FILE="$(mktemp)"
if ! kubectl -n "${NS}" get events -o json > "${EVENTS_JSON_FILE}" 2>/dev/null; then
  printf '{"items":[]}\n' > "${EVENTS_JSON_FILE}"
fi

echo
echo "[*] Computing metrics"
"${PYTHON_BIN}" "${HELPER_SCRIPT}" \
  --pods-json "${PODS_JSON_FILE}" \
  --events-json "${EVENTS_JSON_FILE}" \
  --label "${LABEL}" \
  --target "${TARGET}" \
  --mode "${MODE}" \
  --requested-count "${POD_COUNT}" \
  --workload-sleep "${WORKLOAD_SLEEP_SECONDS}" \
  --submit-start "${SUBMIT_START_ISO}" \
  --submit-end "${SUBMIT_END_ISO}" \
  --finish "${FINISH_ISO}" \
  --run-id "${RUN_ID}" \
  --kubeconfig "${KUBECONFIG}" \
  --out "${RESULT_FILE}"

echo "[*] Result JSON: ${RESULT_FILE}"

if [[ "${CLEANUP}" == "true" ]]; then
  echo "[*] Cleaning up resources for run ${RUN_LABEL}"
  if [[ "${MODE}" == "job" ]]; then
    kubectl -n "${NS}" delete job "${RUN_LABEL}" --wait=false --ignore-not-found=true >/dev/null
  fi
  kubectl -n "${NS}" delete pods -l "${SELECTOR}" --wait=false --ignore-not-found=true >/dev/null
else
  echo "[*] Leaving resources in place. Selector: ${SELECTOR}"
fi
