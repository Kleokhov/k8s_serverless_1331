#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_LOCAL_DIR="${REPO_LOCAL_DIR:-$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel 2>/dev/null || (cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd))}"
OUT_DIR="${OUT_DIR:-${REPO_LOCAL_DIR}/_serverless_out}"
EC2_OUT_DIR="${EC2_OUT_DIR:-${REPO_LOCAL_DIR}/_ec2_out}"

POD_COUNT=""
TARGET=""
MODE="pods"
RUNS="1"
WORKLOAD_SLEEP_SECONDS="10"
NS="latency-test"
LABEL=""
RESULTS_DIR="${OUT_DIR}/latency_results"
WAIT_TIMEOUT_SECONDS="900"
POLL_INTERVAL_SECONDS="2"
CLEANUP="true"
POD_CPU_REQUEST="1m"
POD_MEMORY_REQUEST="4Mi"
IMAGE="busybox:1.36"
IMAGE_PULL_POLICY="IfNotPresent"
PYTHON_BIN="${PYTHON_BIN:-python3}"
HELPER_SCRIPT="${SCRIPT_DIR}/latency_metrics.py"
AGGREGATE_SCRIPT="${SCRIPT_DIR}/latency_aggregate.py"
KUBECTL_APPLY_ATTEMPTS="${KUBECTL_APPLY_ATTEMPTS:-8}"
CLEANUP_WAIT_SECONDS="${CLEANUP_WAIT_SECONDS:-120}"
MANIFEST_APPLIED=0
CLEANUP_DONE=0
RUN_LABEL=""
SELECTOR=""
TEMP_FILES=()
# LATENCY_PER_POD_EVENT_FALLBACK=1

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
  --runs N                 Repeat this same setting N times and print/write a
                           final aggregate report. Default 1.
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
  --cpu / --memory         Per-pod requests, defaults 5m / 16Mi.

Environment:
  KUBECTL_APPLY_ATTEMPTS   Retries for transient DynamoDB transaction
                           contention during the initial apply. Default 8.
  CLEANUP_WAIT_SECONDS     Between repeated runs, wait this long for the prior
                           run's pods/job to disappear after cleanup. Default 120.

Output:
  Writes <results-dir>/<label>_<mode>_n<N>_<run_id>.json with all per-pod
  timestamps and aggregates, and prints a human summary table to stdout.
  Also writes <results-dir>/<label>_<mode>_n<N>_<run_id>_comparison.json
  with batch-relative node-pickup latency percentiles and throughput for
  serverful/serverless comparison plots.
  With --runs N > 1, also writes
  <results-dir>/<label>_<mode>_n<N>_runs<N>_<batch_id>_aggregate.json and
  <results-dir>/<label>_<mode>_n<N>_runs<N>_<batch_id>_aggregate_comparison.json.

Examples:
  # Serverless, 100 pods
  ./scripts/test/test_latency.sh --count 100 --target serverless

  # Serverless, 10 pods repeated 5 times with final averages
  ./scripts/test/test_latency.sh --count 10 --runs 5 --target serverless

  # EC2 cluster, sweep across sizes
  for n in 10 50 100 500; do
    ./scripts/test/test_latency.sh --count "$n" --target serverful
  done

  # Compare via Job mode
  ./scripts/test/test_latency.sh --count 50 --mode job --target serverless
EOF_USAGE
}

cleanup_temp_files() {
  local path
  for path in "${TEMP_FILES[@]:-}"; do
    [[ -n "${path}" ]] || continue
    rm -f "${path}"
  done
}

cleanup_run_resources() {
  if [[ "${CLEANUP_DONE}" == "1" || "${CLEANUP}" != "true" || "${MANIFEST_APPLIED}" != "1" ]]; then
    return 0
  fi
  if [[ -z "${RUN_LABEL:-}" || -z "${SELECTOR:-}" ]]; then
    return 0
  fi

  CLEANUP_DONE=1
  echo "[*] Cleaning up resources for run ${RUN_LABEL}"
  if [[ "${MODE}" == "job" ]]; then
    kubectl -n "${NS}" delete job "${RUN_LABEL}" --wait=false --ignore-not-found=true >/dev/null || true
  fi
  kubectl -n "${NS}" delete pods -l "${SELECTOR}" --wait=false --ignore-not-found=true >/dev/null || true
}

on_exit() {
  local status=$?
  if (( status != 0 )); then
    cleanup_run_resources >&2 || true
  fi
  cleanup_temp_files
}

trap on_exit EXIT

while (( $# > 0 )); do
  case "$1" in
    --count)         POD_COUNT="$2"; shift 2 ;;
    --target)        TARGET="$2"; shift 2 ;;
    --mode)          MODE="$2"; shift 2 ;;
    --runs|--repeat) RUNS="$2"; shift 2 ;;
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
if ! [[ "${RUNS}" =~ ^[1-9][0-9]*$ ]]; then
  echo "--runs must be a positive integer, got: ${RUNS}" >&2
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
if ! [[ "${CLEANUP_WAIT_SECONDS}" =~ ^[1-9][0-9]*$ ]]; then
  echo "CLEANUP_WAIT_SECONDS must be a positive integer, got: ${CLEANUP_WAIT_SECONDS}" >&2
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
if [[ ! -f "${AGGREGATE_SCRIPT}" ]]; then
  echo "Aggregate helper script missing: ${AGGREGATE_SCRIPT}" >&2
  exit 1
fi

mkdir -p "${RESULTS_DIR}"

SAFE_LABEL="$(printf '%s' "${LABEL}" | tr -c 'a-zA-Z0-9._-' '-' | tr '[:upper:]' '[:lower:]')"
APP_LABEL="latency-test"
BATCH_ID="$(date -u +%Y%m%d%H%M%S)"
AGGREGATE_FILE="${RESULTS_DIR}/${SAFE_LABEL}_${MODE}_n${POD_COUNT}_runs${RUNS}_${BATCH_ID}_aggregate.json"
AGGREGATE_COMPARISON_FILE="${AGGREGATE_FILE%.json}_comparison.json"

echo "[*] Target:           ${TARGET:-(KUBECONFIG override)}"
echo "[*] Kubeconfig:       ${KUBECONFIG}"
echo "[*] Namespace:        ${NS}"
echo "[*] Pod count:        ${POD_COUNT}"
echo "[*] Mode:             ${MODE}"
echo "[*] Runs:             ${RUNS}"
echo "[*] Workload sleep:   ${WORKLOAD_SLEEP_SECONDS}s"
if (( RUNS > 1 )); then
  echo "[*] Aggregate file:   ${AGGREGATE_FILE}"
  echo "[*] Comparison file:  ${AGGREGATE_COMPARISON_FILE}"
fi

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

warn_existing_latency_pods() {
  local pods_file count summary sample
  pods_file="$(mktemp)"
  TEMP_FILES+=("${pods_file}")

  if ! kubectl -n "${NS}" get pods -l "app=${APP_LABEL}" --chunk-size=0 -o json > "${pods_file}" 2>/dev/null; then
    return 0
  fi

  count="$("${PYTHON_BIN}" -c '
import json
import sys

data = json.load(open(sys.argv[1]))
items = [
    pod for pod in data.get("items") or []
    if ((pod.get("metadata") or {}).get("labels") or {}).get("run") != sys.argv[2]
]
print(len(items))
' "${pods_file}" "${RUN_LABEL}")"
  count="${count:-0}"
  if (( count == 0 )); then
    return 0
  fi

  summary="$("${PYTHON_BIN}" -c '
import collections
import json
import sys

data = json.load(open(sys.argv[1]))
items = [
    pod for pod in data.get("items") or []
    if ((pod.get("metadata") or {}).get("labels") or {}).get("run") != sys.argv[2]
]
counts = collections.Counter(((pod.get("status") or {}).get("phase") or "Unknown") for pod in items)
print(" ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none")
' "${pods_file}" "${RUN_LABEL}")"
  sample="$("${PYTHON_BIN}" -c '
import json
import sys

data = json.load(open(sys.argv[1]))
items = [
    pod for pod in data.get("items") or []
    if ((pod.get("metadata") or {}).get("labels") or {}).get("run") != sys.argv[2]
]
print(", ".join((pod.get("metadata") or {}).get("name", "") for pod in items[:5]))
' "${pods_file}" "${RUN_LABEL}")"

  echo "[!] Found ${count} existing ${APP_LABEL} pod(s) in namespace ${NS}: ${summary}"
  echo "[!] Existing assigned pods can skew scheduling/admission tests. Sample: ${sample}"
}

warn_requested_cpu_capacity() {
  local nodes_file
  nodes_file="$(mktemp)"
  TEMP_FILES+=("${nodes_file}")

  if ! kubectl get nodes -o json > "${nodes_file}" 2>/dev/null; then
    return 0
  fi

"${PYTHON_BIN}" -c '
import json
import sys

nodes_path, pod_count_raw, request = sys.argv[1:4]

def cpu_millicores(value):
    value = str(value or "0").strip()
    if not value:
        return 0
    if value.endswith("m"):
        return int(value[:-1])
    return int(float(value) * 1000)

try:
    pod_count = int(pod_count_raw)
    pod_request_m = cpu_millicores(request)
    nodes = json.load(open(nodes_path)).get("items") or []
except Exception:
    raise SystemExit(0)

allocatable_m = 0
for node in nodes:
    allocatable = (node.get("status") or {}).get("allocatable") or {}
    allocatable_m += cpu_millicores(allocatable.get("cpu"))

requested_m = pod_count * pod_request_m
if allocatable_m > 0 and requested_m > allocatable_m:
    suggested = max(1, allocatable_m // pod_count)
    print(
        f"[!] Requested aggregate CPU {requested_m}m exceeds cluster allocatable CPU {allocatable_m}m. "
        f"Pods may remain Pending or be rejected by kubelet admission (OutOfcpu)."
    )
    print(f"[!] For this count on current nodes, use --cpu {suggested}m or lower, reduce --count, or add workers.")
' "${nodes_file}" "${POD_COUNT}" "${POD_CPU_REQUEST}"
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

pending = counts.get("Pending", 0)
running = counts.get("Running", 0)
succeeded = counts.get("Succeeded", 0)
failed = counts.get("Failed", 0)
unknown = counts.get("Unknown", 0)
print(
    f"total={total} pending={pending} running={running} "
    f"succeeded={succeeded} failed={failed} unknown={unknown}"
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

filter_events_for_pods() {
  local pods_json_file="$1"
  local output_file="$2"
  shift 2

  "${PYTHON_BIN}" -c '
import json
import os
import sys

pods_path, output_path, *event_paths = sys.argv[1:]

def read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"items": []}

pods = read_json(pods_path).get("items") or []
pod_uids = set()
pod_names = set()
pod_namespace_names = set()
for pod in pods:
    meta = pod.get("metadata") or {}
    uid = meta.get("uid")
    name = meta.get("name")
    namespace = meta.get("namespace")
    if uid:
        pod_uids.add(uid)
    if name:
        pod_names.add(name)
    if namespace and name:
        pod_namespace_names.add(f"{namespace}/{name}")

def event_ref(ev):
    return ev.get("involvedObject") or ev.get("regarding") or {}

def event_key(ev):
    meta = ev.get("metadata") or {}
    namespace = meta.get("namespace", "")
    name = meta.get("name", "")
    return meta.get("uid") or f"{namespace}/{name}" or json.dumps(ev, sort_keys=True)

def event_time(ev):
    meta = ev.get("metadata") or {}
    series = ev.get("series") or {}
    return (
        ev.get("eventTime")
        or series.get("lastObservedTime")
        or ev.get("firstTimestamp")
        or ev.get("lastTimestamp")
        or ev.get("deprecatedFirstTimestamp")
        or ev.get("deprecatedLastTimestamp")
        or meta.get("creationTimestamp")
        or ""
    )

items = []
seen = set()
for event_path in event_paths:
    for ev in read_json(event_path).get("items") or []:
        ref = event_ref(ev)
        if ref.get("kind") != "Pod":
            continue
        namespace = ref.get("namespace")
        name = ref.get("name")
        matches = (
            (ref.get("uid") and ref.get("uid") in pod_uids)
            or (name and name in pod_names)
            or (namespace and name and f"{namespace}/{name}" in pod_namespace_names)
        )
        if not matches:
            continue
        key = event_key(ev)
        if key in seen:
            continue
        seen.add(key)
        items.append(ev)

items.sort(key=lambda ev: (event_time(ev), (ev.get("metadata") or {}).get("name", "")))
out = {"apiVersion": "v1", "kind": "EventList", "items": items}
tmp_path = output_path + ".tmp"
with open(tmp_path, "w") as f:
    json.dump(out, f)
os.replace(tmp_path, output_path)
' "${pods_json_file}" "${output_file}" "$@"
}

json_item_count() {
  local json_file="$1"
  "${PYTHON_BIN}" -c '
import json
import sys

try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except (OSError, json.JSONDecodeError):
    print(0)
    raise SystemExit(0)
print(len(data.get("items") or []))
' "${json_file}"
}

event_pod_count_from_file() {
  local events_json_file="$1"
  "${PYTHON_BIN}" -c '
import json
import sys

try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except (OSError, json.JSONDecodeError):
    print(0)
    raise SystemExit(0)

pods = set()
for ev in data.get("items") or []:
    ref = ev.get("involvedObject") or ev.get("regarding") or {}
    if ref.get("kind") != "Pod":
        continue
    namespace = ref.get("namespace", "")
    name = ref.get("name", "")
    key = ref.get("uid") or f"{namespace}/{name}" or name
    if key:
        pods.add(key)
print(len(pods))
' "${events_json_file}"
}

pod_names_from_file() {
  local pods_json_file="$1"
  "${PYTHON_BIN}" -c '
import json
import sys

try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except (OSError, json.JSONDecodeError):
    raise SystemExit(0)
for pod in data.get("items") or []:
    name = ((pod.get("metadata") or {}).get("name") or "").strip()
    if name:
        print(name)
' "${pods_json_file}"
}

collect_run_events() {
  local pods_json_file="$1"
  local output_file="$2"
  local namespace_events_file pod_count event_count event_pod_count pod_name pod_events_file
  local event_files=()

  namespace_events_file="$(mktemp)"
  TEMP_FILES+=("${namespace_events_file}")
  if kubectl -n "${NS}" get events --chunk-size=0 -o json > "${namespace_events_file}" 2>/dev/null; then
    event_files+=("${namespace_events_file}")
  else
    printf '{"items":[]}\n' > "${namespace_events_file}"
  fi

  filter_events_for_pods "${pods_json_file}" "${output_file}" "${event_files[@]}"
  pod_count="$(json_item_count "${pods_json_file}")"
  pod_count="${pod_count:-0}"
  event_count="$(json_item_count "${output_file}")"
  event_count="${event_count:-0}"
  event_pod_count="$(event_pod_count_from_file "${output_file}")"
  event_pod_count="${event_pod_count:-0}"

  # Per-pod fallback fires one kubectl invocation per pod. On the no-watch
  # apiserver this can be hundreds of seconds for a 500+ pod run. Off by
  # default; opt in with LATENCY_PER_POD_EVENT_FALLBACK=1 if you really need
  # complete event coverage and accept the post-processing wall time.
  if [[ "${LATENCY_PER_POD_EVENT_FALLBACK:-0}" == "1" ]] && (( event_pod_count < pod_count )); then
    while IFS= read -r pod_name; do
      [[ -n "${pod_name}" ]] || continue
      pod_events_file="$(mktemp)"
      TEMP_FILES+=("${pod_events_file}")
      if kubectl -n "${NS}" get events \
        --field-selector "involvedObject.name=${pod_name}" \
        --chunk-size=0 \
        -o json > "${pod_events_file}" 2>/dev/null; then
        event_files+=("${pod_events_file}")
      fi
    done < <(pod_names_from_file "${pods_json_file}")
    filter_events_for_pods "${pods_json_file}" "${output_file}" "${event_files[@]}"
    event_count="$(json_item_count "${output_file}")"
    event_count="${event_count:-0}"
    event_pod_count="$(event_pod_count_from_file "${output_file}")"
    event_pod_count="${event_pod_count:-0}"
  fi

  echo "[*] Captured ${event_count} event(s) for run ${RUN_LABEL} (${event_pod_count}/${pod_count} observed pod(s))"
  if (( event_pod_count < pod_count )); then
    echo "[!] Events are missing for $((pod_count - event_pod_count)) observed pod(s); set LATENCY_PER_POD_EVENT_FALLBACK=1 to fetch them per-pod (slow)."
  fi
}


write_comparison_metrics() {
  local result_file="$1"
  local output_file="$2"
  local submit_start_iso="$3"
  local requested_count="$4"

  "${PYTHON_BIN}" - "${result_file}" "${output_file}" "${submit_start_iso}" "${requested_count}" <<'PY'
import datetime as _dt
import json
import math
import re
import sys
from typing import Any, Iterable

result_path, output_path, submit_start_raw, requested_count_raw = sys.argv[1:5]

def parse_time(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            return float(s)
        except ValueError:
            pass
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            return _dt.datetime.fromisoformat(s).timestamp()
        except ValueError:
            return None
    return None

def norm_key(key):
    return re.sub(r"[^a-z0-9]", "", str(key).lower())

def iter_dicts(obj):
    if isinstance(obj, dict):
        yield obj
        for value in obj.values():
            yield from iter_dicts(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from iter_dicts(value)

def find_first_timestamp(obj, key_predicate):
    if not isinstance(obj, (dict, list)):
        return None
    for d in iter_dicts(obj):
        for key, value in d.items():
            if key_predicate(norm_key(key)):
                ts = parse_time(value)
                if ts is not None:
                    return ts
    return None

def collect_pod_records(data):
    candidate_paths = [
        ("pods",), ("items",), ("per_pod",), ("perPod",),
        ("per_pod_results",), ("pod_results",), ("pod_metrics",),
        ("podMetrics",), ("results", "pods"), ("metrics", "pods"),
    ]
    def get_path(obj, path):
        cur = obj
        for part in path:
            if not isinstance(cur, dict) or part not in cur:
                return None
            cur = cur[part]
        return cur
    candidates = []
    for path in candidate_paths:
        value = get_path(data, path)
        if isinstance(value, list) and value and all(isinstance(x, dict) for x in value):
            candidates.append(value)
    def walk_lists(obj):
        if isinstance(obj, list):
            if obj and all(isinstance(x, dict) for x in obj):
                yield obj
            for value in obj:
                yield from walk_lists(value)
        elif isinstance(obj, dict):
            for value in obj.values():
                yield from walk_lists(value)
    candidates.extend(walk_lists(data))
    best = []
    best_score = -1
    for candidate in candidates:
        score = 0
        for row in candidate:
            has_name = any(norm_key(k) in {"name", "pod", "podname"} for k in row)
            has_node_pickup = find_first_timestamp(row, lambda k: ("node" in k and "pickup" in k) or k in {"nodepickup", "nodepickuptime", "nodepickuptimestamp"}) is not None
            has_dispatch = find_first_timestamp(row, lambda k: "dispatch" in k or "dispatched" in k) is not None
            has_started = find_first_timestamp(row, lambda k: "start" in k or "started" in k) is not None
            if has_name:
                score += 1
            if has_node_pickup or has_dispatch:
                score += 4
            if has_started:
                score += 1
        if score > best_score:
            best = candidate
            best_score = score
    out = []
    seen = set()
    for row in best:
        if not isinstance(row, dict):
            continue
        name = None
        for d in iter_dicts(row):
            for key, value in d.items():
                if norm_key(key) in {"uid", "name", "podname", "pod"} and isinstance(value, str):
                    name = value
                    break
            if name:
                break
        key = name or id(row)
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out

def percentile(values, q):
    if not values:
        return None
    values = sorted(values)
    if len(values) == 1:
        return values[0]
    pos = (len(values) - 1) * (q / 100.0)
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return values[int(pos)]
    frac = pos - lo
    return values[lo] * (1.0 - frac) + values[hi] * frac

def fmt(value, suffix="s"):
    if value is None:
        return "n/a"
    return f"{value:.3f}{suffix}"

try:
    requested_count = int(requested_count_raw)
except ValueError:
    requested_count = None
batch_start = parse_time(submit_start_raw)
warnings = []
if batch_start is None:
    warnings.append(f"Could not parse submit-start timestamp: {submit_start_raw!r}")
try:
    with open(result_path) as f:
        data = json.load(f)
except Exception as exc:
    print(f"[!] Could not load metrics JSON for comparison metrics: {result_path}: {exc}")
    raise SystemExit(0)
records = collect_pod_records(data)
node_pickup_offsets = []
missing_node_pickup = 0
for record in records:
    node_pickup_ts = find_first_timestamp(record, lambda k: ("node" in k and "pickup" in k) or k in {"nodepickup", "nodepickuptime", "nodepickuptimestamp"})
    if node_pickup_ts is None:
        node_pickup_ts = find_first_timestamp(record, lambda k: "dispatch" in k or "dispatched" in k)
    if batch_start is not None and node_pickup_ts is not None:
        offset = node_pickup_ts - batch_start
        if offset >= -0.001:
            node_pickup_offsets.append(max(0.0, offset))
    else:
        missing_node_pickup += 1
if not records:
    warnings.append("Could not find per-pod records in the helper JSON; comparison metrics were not computed.")
if records and not node_pickup_offsets:
    warnings.append("Found per-pod records, but no node-pickup/dispatch timestamps were extractable.")
observed_node_pickups = len(node_pickup_offsets)
node_pickup_window = max(node_pickup_offsets) if node_pickup_offsets else None
node_pickup_throughput = (observed_node_pickups / node_pickup_window) if node_pickup_window and node_pickup_window > 0 else None
lat = {
    "n": observed_node_pickups,
    "avg": (sum(node_pickup_offsets) / observed_node_pickups) if observed_node_pickups else None,
    "min": min(node_pickup_offsets) if node_pickup_offsets else None,
    "p50": percentile(node_pickup_offsets, 50),
    "p95": percentile(node_pickup_offsets, 95),
    "p99": percentile(node_pickup_offsets, 99),
    "max": node_pickup_window,
}
summary = {
    "comparison_metrics_version": 1,
    "definition": {
        "human_label": "end-to-end",
        "human_label_definition": "submit -> node pickup",
        "batch_relative_node_pickup_latency_seconds": "node_pickup_time_i - run_submit_start_time",
        "batch_node_pickup_window_seconds": "max(node_pickup_time_i - run_submit_start_time)",
        "node_pickup_throughput_pods_per_sec": "observed_node_pickups / batch_node_pickup_window_seconds",
        "note": "This is the comparison-safe end-to-end metric for latency-vs-N plots because it uses one batch start time for every pod.",
    },
    "source_result_file": result_path,
    "batch_submit_start": submit_start_raw,
    "requested_count": requested_count,
    "pod_records_found": len(records),
    "observed_node_pickups": observed_node_pickups,
    "missing_node_pickup_timestamps": missing_node_pickup,
    "batch_node_pickup_window_seconds": node_pickup_window,
    "node_pickup_throughput_pods_per_sec": node_pickup_throughput,
    "batch_relative_node_pickup_latency_seconds": lat,
    "node_pickup_offsets_seconds": sorted(node_pickup_offsets),
    "warnings": warnings,
}
with open(output_path, "w") as f:
    json.dump(summary, f, indent=2, sort_keys=True)
    f.write("\n")

def fmt_stats(stats):
    return (
        f"n={stats['n']}  "
        f"avg={fmt(stats['avg'])}  "
        f"min={fmt(stats['min'])}  "
        f"p50={fmt(stats['p50'])}  "
        f"p95={fmt(stats['p95'])}  "
        f"p99={fmt(stats['p99'])}  "
        f"max={fmt(stats['max'])}"
    )

print("\n=== Comparison-safe end-to-end report ===")
print("  Files")
print(f"    output:              {output_path}")
print("  Counts")
print(f"    requested pods:      {requested_count if requested_count is not None else 'n/a'}")
print(f"    pod records found:   {len(records)}")
print(f"    observed samples:    {observed_node_pickups}")
print("  End-to-end")
print(f"    window:              {fmt(node_pickup_window)}")
print(f"    throughput:          {fmt(node_pickup_throughput, ' pods/sec')}")
print(f"    latency:             {fmt_stats(lat)}")
for warning in warnings:
    print(f"  [!] {warning}")
PY
}

write_comparison_aggregate() {
  local output_file="$1"
  shift

  "${PYTHON_BIN}" - "${output_file}" "$@" <<'PY'
import json
import math
import sys

output_path, *paths = sys.argv[1:]

def percentile(values, q):
    values = sorted(values)
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    pos = (len(values) - 1) * (q / 100.0)
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return values[int(pos)]
    frac = pos - lo
    return values[lo] * (1.0 - frac) + values[hi] * frac

def mean(values):
    values = [v for v in values if isinstance(v, (int, float))]
    return sum(values) / len(values) if values else None

def fmt(value, suffix="s"):
    if value is None:
        return "n/a"
    return f"{value:.3f}{suffix}"

runs = []
pooled_node_pickup_offsets = []
warnings = []
for path in paths:
    try:
        with open(path) as f:
            run = json.load(f)
    except Exception as exc:
        warnings.append(f"Could not load {path}: {exc}")
        continue
    runs.append(run)
    pooled_node_pickup_offsets.extend(run.get("node_pickup_offsets_seconds") or [])
    warnings.extend(run.get("warnings") or [])
node_windows = [r.get("batch_node_pickup_window_seconds") for r in runs]
node_tputs = [r.get("node_pickup_throughput_pods_per_sec") for r in runs]
summary = {
    "comparison_aggregate_version": 1,
    "definition": {
        "human_label": "end-to-end",
        "human_label_definition": "submit -> node pickup",
        "run_level_avg_batch_node_pickup_window_seconds": "mean across runs of max(node_pickup_time_i - run_submit_start_time)",
        "run_level_avg_node_pickup_throughput_pods_per_sec": "mean across runs of observed_node_pickups / batch_node_pickup_window_seconds",
        "pooled_batch_relative_node_pickup_latency_seconds": "percentiles over all pod node-pickup offsets from all runs",
    },
    "run_count": len(runs),
    "source_comparison_files": paths,
    "requested_count": runs[0].get("requested_count") if runs else None,
    "observed_node_pickups_total": sum((r.get("observed_node_pickups") or 0) for r in runs),
    "run_level": {
        "batch_node_pickup_window_seconds": {"avg": mean(node_windows), "min": min([v for v in node_windows if isinstance(v, (int, float))], default=None), "max": max([v for v in node_windows if isinstance(v, (int, float))], default=None)},
        "node_pickup_throughput_pods_per_sec": {"avg": mean(node_tputs), "min": min([v for v in node_tputs if isinstance(v, (int, float))], default=None), "max": max([v for v in node_tputs if isinstance(v, (int, float))], default=None)},
    },
    "pooled_batch_relative_node_pickup_latency_seconds": {"n": len(pooled_node_pickup_offsets), "avg": mean(pooled_node_pickup_offsets), "min": min(pooled_node_pickup_offsets) if pooled_node_pickup_offsets else None, "p50": percentile(pooled_node_pickup_offsets, 50), "p95": percentile(pooled_node_pickup_offsets, 95), "p99": percentile(pooled_node_pickup_offsets, 99), "max": max(pooled_node_pickup_offsets) if pooled_node_pickup_offsets else None},
    "warnings": sorted(set(warnings)),
}
with open(output_path, "w") as f:
    json.dump(summary, f, indent=2, sort_keys=True)
    f.write("\n")
lat = summary["pooled_batch_relative_node_pickup_latency_seconds"]
run_node_window = summary["run_level"]["batch_node_pickup_window_seconds"]
run_node_tput = summary["run_level"]["node_pickup_throughput_pods_per_sec"]

def fmt_stats(stats):
    return (
        f"n={stats['n']}  "
        f"avg={fmt(stats['avg'])}  "
        f"min={fmt(stats['min'])}  "
        f"p50={fmt(stats['p50'])}  "
        f"p95={fmt(stats['p95'])}  "
        f"p99={fmt(stats['p99'])}  "
        f"max={fmt(stats['max'])}"
    )

print("\n=== Aggregate comparison-safe end-to-end report ===")
print("  Files")
print(f"    output:              {output_path}")
print("  Counts")
print(f"    runs:                {summary['run_count']}")
print(f"    requested pods/run:  {summary['requested_count']}")
print(f"    observed samples:    {summary['observed_node_pickups_total']}")
print("  End-to-end run level")
print(f"    window:              avg={fmt(run_node_window['avg'])}  min={fmt(run_node_window['min'])}  max={fmt(run_node_window['max'])}")
print(f"    throughput:          avg={fmt(run_node_tput['avg'], ' pods/sec')}  min={fmt(run_node_tput['min'], ' pods/sec')}  max={fmt(run_node_tput['max'], ' pods/sec')}")
print("  End-to-end pooled latency")
print(f"    {fmt_stats(lat)}")
for warning in summary["warnings"]:
    print(f"  [!] {warning}")
PY
}

run_resource_count() {
  local count
  count="$({ kubectl -n "${NS}" get pods -l "${SELECTOR}" --chunk-size=0 -o name 2>/dev/null || true; } | wc -l | tr -d '[:space:]')"
  count="${count:-0}"
  if [[ "${MODE}" == "job" ]]; then
    local job_count
    job_count="$({ kubectl -n "${NS}" get job "${RUN_LABEL}" -o name 2>/dev/null || true; } | wc -l | tr -d '[:space:]')"
    job_count="${job_count:-0}"
    count=$(( count + job_count ))
  fi
  echo "${count}"
}

wait_for_run_resources_gone() {
  local deadline now count
  deadline=$(($(date +%s) + CLEANUP_WAIT_SECONDS))
  while :; do
    count="$(run_resource_count)"
    if (( count == 0 )); then
      return 0
    fi
    now="$(date +%s)"
    if (( now >= deadline )); then
      echo "[!] ${count} resource(s) from ${RUN_LABEL} are still visible after cleanup wait; next run may see leftover resource pressure."
      return 0
    fi
    sleep 1
  done
}

run_once() {
  local run_index="$1"
  local run_header run_suffix
  local manifest_file pods_json_file events_json_file
  local apply_status
  local submit_start_epoch submit_end_epoch deadline last_status_print
  local now phase_counts total pending running succeeded failed unknown start_counts started start_or_failed
  local terminal stall_started_at last_progress_signature progress_signature
  local stall_seconds

  MANIFEST_APPLIED=0
  CLEANUP_DONE=0

  if (( RUNS == 1 )); then
    RUN_ID="${BATCH_ID}"
    run_header="run 1/1"
  else
    run_suffix="$(printf 'r%02d' "${run_index}")"
    RUN_ID="${BATCH_ID}-${run_suffix}"
    run_header="run ${run_index}/${RUNS}"
  fi
  RUN_LABEL="latency-${SAFE_LABEL}-${RUN_ID}"
  SELECTOR="app=${APP_LABEL},run=${RUN_LABEL}"
  RESULT_FILE="${RESULTS_DIR}/${SAFE_LABEL}_${MODE}_n${POD_COUNT}_${RUN_ID}.json"
  RESULT_BASE="${RESULT_FILE%.json}"
  PODS_RESULT_FILE="${RESULT_BASE}_pods.json"
  EVENTS_RESULT_FILE="${RESULT_BASE}_events.json"
  COMPARISON_RESULT_FILE="${RESULT_BASE}_comparison.json"

  echo
  echo "== Latency ${run_header} =="
  echo "[*] Run label:        ${RUN_LABEL}"
  echo "[*] Result file:      ${RESULT_FILE}"

  warn_existing_latency_pods

  manifest_file="$(mktemp)"
  pods_json_file="$(mktemp)"
  TEMP_FILES+=("${manifest_file}" "${pods_json_file}")
  printf '{"apiVersion":"v1","kind":"PodList","items":[]}\n' > "${pods_json_file}"
  build_manifest > "${manifest_file}"

  SUBMIT_START_ISO="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  submit_start_epoch="$(date +%s)"
  echo "[*] Submitting at ${SUBMIT_START_ISO}"

  MANIFEST_APPLIED=1
  apply_status=0
  kubectl_apply_manifest "${manifest_file}" || apply_status=$?
  if (( apply_status != 0 )); then
    return "${apply_status}"
  fi

  SUBMIT_END_ISO="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  submit_end_epoch="$(date +%s)"
  echo "[*] Submitted in $((submit_end_epoch - submit_start_epoch))s, polling for pod start (timeout ${WAIT_TIMEOUT_SECONDS}s)"

  deadline=$((submit_end_epoch + WAIT_TIMEOUT_SECONDS))
  last_status_print=0
  stall_started_at=0
  last_progress_signature=""
  stall_seconds="${LATENCY_STALL_SECONDS:-30}"
  while :; do
    now=$(date +%s)
    if (( now >= deadline )); then
      echo "[!] Timed out waiting for pods to start; capturing whatever state we have"
      break
    fi

    if ! kubectl -n "${NS}" get pods -l "${SELECTOR}" --chunk-size=0 -o json > "${pods_json_file}" 2>/dev/null; then
      printf '{"apiVersion":"v1","kind":"PodList","items":[]}\n' > "${pods_json_file}"
    fi

    phase_counts="$(pod_phase_counts_from_file "${pods_json_file}")"
    total="$(phase_count_value "${phase_counts}" total)"
    pending="$(phase_count_value "${phase_counts}" pending)"
    running="$(phase_count_value "${phase_counts}" running)"
    succeeded="$(phase_count_value "${phase_counts}" succeeded)"
    failed="$(phase_count_value "${phase_counts}" failed)"
    unknown="$(phase_count_value "${phase_counts}" unknown)"
    start_counts="$(pod_start_counts_from_file "${pods_json_file}")"
    started="$(phase_count_value "${start_counts}" started)"
    start_or_failed="$(phase_count_value "${start_counts}" start_or_failed)"
    total="${total:-0}"
    pending="${pending:-0}"
    running="${running:-0}"
    succeeded="${succeeded:-0}"
    failed="${failed:-0}"
    unknown="${unknown:-0}"
    started="${started:-0}"
    start_or_failed="${start_or_failed:-0}"
    terminal=$(( succeeded + failed ))

    if (( now - last_status_print >= 5 )); then
      echo "[*] $(date -u '+%H:%M:%SZ') current ${phase_counts} started=${started}/${POD_COUNT} terminal=${terminal}/${POD_COUNT}"
      last_status_print="${now}"
    fi

    # Success: every requested pod has started or has failed before starting.
    if (( start_or_failed >= POD_COUNT )); then
      if (( started >= POD_COUNT )); then
        echo "[*] All ${POD_COUNT} pods started"
      else
        echo "[*] All ${POD_COUNT} pods started or failed before start"
      fi
      break
    fi

    # No-progress stall detector. The progress signature combines counters that
    # only ever move forward in a healthy run; if it stops changing while no
    # pods are pending or running, we give up rather than wait for the timeout.
    progress_signature="${total}/${started}/${start_or_failed}/${terminal}"
    if [[ "${progress_signature}" != "${last_progress_signature}" ]]; then
      last_progress_signature="${progress_signature}"
      stall_started_at="${now}"
    elif (( pending == 0 && running == 0 && unknown == 0 && now - stall_started_at >= stall_seconds )); then
      echo "[!] No progress for ${stall_seconds}s and no pods pending/running; only ${start_or_failed}/${POD_COUNT} pods were observed to start or fail."
      echo "[!] Capturing whatever state we have. Set LATENCY_STALL_SECONDS to tune this threshold."
      break
    fi

    sleep "${POLL_INTERVAL_SECONDS}"
  done

  FINISH_ISO="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

  events_json_file="$(mktemp)"
  TEMP_FILES+=("${events_json_file}")
  collect_run_events "${pods_json_file}" "${events_json_file}"

  cp "${pods_json_file}" "${PODS_RESULT_FILE}"
  cp "${events_json_file}" "${EVENTS_RESULT_FILE}"

  echo
  echo "[*] Computing metrics"
  "${PYTHON_BIN}" "${HELPER_SCRIPT}" \
    --pods-json "${pods_json_file}" \
    --events-json "${events_json_file}" \
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

  RESULT_FILES+=("${RESULT_FILE}")

  echo "[*] Result JSON: ${RESULT_FILE}"
  echo "[*] Pod snapshot JSON: ${PODS_RESULT_FILE}"
  echo "[*] Events JSON: ${EVENTS_RESULT_FILE}"

  echo
  echo "[*] Computing comparison-safe batch-relative metrics"
  write_comparison_metrics \
    "${RESULT_FILE}" \
    "${COMPARISON_RESULT_FILE}" \
    "${SUBMIT_START_ISO}" \
    "${POD_COUNT}"
  COMPARISON_METRICS_FILES+=("${COMPARISON_RESULT_FILE}")
  echo "[*] Comparison JSON: ${COMPARISON_RESULT_FILE}"

  if [[ "${CLEANUP}" == "true" ]]; then
    cleanup_run_resources
    if (( run_index < RUNS )); then
      wait_for_run_resources_gone
    fi
  else
    echo "[*] Leaving resources in place. Selector: ${SELECTOR}"
  fi
}

RESULT_FILES=()
COMPARISON_METRICS_FILES=()
warn_requested_cpu_capacity

for ((run_index = 1; run_index <= RUNS; run_index++)); do
  run_once "${run_index}"
done

if (( RUNS > 1 )); then
  echo
  echo "[*] Computing aggregate metrics"
  "${PYTHON_BIN}" "${AGGREGATE_SCRIPT}" \
    --out "${AGGREGATE_FILE}" \
    "${RESULT_FILES[@]}"
  echo "[*] Aggregate JSON: ${AGGREGATE_FILE}"

  echo
  echo "[*] Computing aggregate comparison-safe batch-relative metrics"
  write_comparison_aggregate \
    "${AGGREGATE_COMPARISON_FILE}" \
    "${COMPARISON_METRICS_FILES[@]}"
  echo "[*] Aggregate comparison JSON: ${AGGREGATE_COMPARISON_FILE}"
fi
