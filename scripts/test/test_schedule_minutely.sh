#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_LOCAL_DIR="${REPO_LOCAL_DIR:-$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel 2>/dev/null || (cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd))}"
OUT_DIR="${OUT_DIR:-${REPO_LOCAL_DIR}/_serverless_out}"

export KUBECONFIG="${KUBECONFIG:-${OUT_DIR}/lambda-apiserver.kubeconfig}"
NS="${NS:-hello-test}"
JOB_BASENAME="${JOB_BASENAME:-normal-workload}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%d%H%M%S)}"
APP_LABEL="${APP_LABEL:-normal-workload}"
RUN_LABEL="${RUN_LABEL:-${JOB_BASENAME}-${RUN_ID}}"
TEST_DURATION_SECONDS="${TEST_DURATION_SECONDS:-3600}"
SUBMISSION_INTERVAL_SECONDS="${SUBMISSION_INTERVAL_SECONDS:-15}"
JOBS_PER_INTERVAL="${JOBS_PER_INTERVAL:-1}"
JOB_COMPLETIONS="${JOB_COMPLETIONS:-4}"
JOB_PARALLELISM="${JOB_PARALLELISM:-4}"
WORK_ITEMS="${WORK_ITEMS:-8000}"
WORKLOAD_SLEEP_SECONDS="${WORKLOAD_SLEEP_SECONDS:-45}"
POD_CPU_REQUEST="${POD_CPU_REQUEST:-50m}"
POD_MEMORY_REQUEST="${POD_MEMORY_REQUEST:-64Mi}"
JOB_TTL_SECONDS="${JOB_TTL_SECONDS:-600}"
WAIT_FOR_COMPLETION="${WAIT_FOR_COMPLETION:-false}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-90m}"
CLEANUP="${CLEANUP:-false}"
MEASURE_COST="${MEASURE_COST:-true}"
MEASURE_COST_TAIL_SECONDS="${MEASURE_COST_TAIL_SECONDS:-120}"
MEASURE_COST_DELAY_SECONDS="${MEASURE_COST_DELAY_SECONDS:-600}"
MEASURE_COST_REGION="${MEASURE_COST_REGION:-${AWS_REGION:-us-east-1}}"
MEASURE_COST_SCRIPT="${MEASURE_COST_SCRIPT:-${SCRIPT_DIR}/measure_cost.py}"
MEASURE_COST_PYTHON="${MEASURE_COST_PYTHON:-python3}"
MEASURE_COST_EXTRA_ARGS="${MEASURE_COST_EXTRA_ARGS:-}"
IMAGE="${IMAGE:-busybox:1.36}"
IMAGE_PULL_POLICY="${IMAGE_PULL_POLICY:-IfNotPresent}"
JOB_SELECTOR="app=${APP_LABEL},run=${RUN_LABEL}"

usage() {
  cat <<'EOF_USAGE'
Usage: ./scripts/test/test_schedule_minutely.sh

Runs a steady Job workload against the serverless pipeline for one hour and
then computes the AWS cost incurred over that window via measure_cost.py. The
shape of the workload is meant to imitate a realistic parallel batch tenant
with moderate control-plane pressure, not a pure stress test:

  - One Job is submitted every SUBMISSION_INTERVAL_SECONDS (default 15s).
  - Each Job creates JOB_COMPLETIONS pods and runs up to JOB_PARALLELISM pods
    concurrently (defaults: 4 completions, 4 parallelism).
  - Each pod runs a small sort-and-checksum workload, then sleeps
    WORKLOAD_SLEEP_SECONDS, so each pod lasts long enough to observe scheduling,
    status updates, completion, and TTL cleanup.
  - The namespace is created once and reused; no rotation, no cascade-delete
    churn during the measured workload.
  - Finished Jobs are reaped JOB_TTL_SECONDS after completion.

Defaults submit ~240 Jobs/hour and ~960 Pods/hour, with roughly a dozen pods
in flight at steady state when pods live for about 45s.

Environment overrides:
  NS=hello-test
  TEST_DURATION_SECONDS=3600
  SUBMISSION_INTERVAL_SECONDS=15
  JOBS_PER_INTERVAL=1
  JOB_COMPLETIONS=4
  JOB_PARALLELISM=4
  WORK_ITEMS=8000
  WORKLOAD_SLEEP_SECONDS=45
  POD_CPU_REQUEST=50m
  POD_MEMORY_REQUEST=64Mi
  JOB_TTL_SECONDS=600
  WAIT_FOR_COMPLETION=false
  WAIT_TIMEOUT=90m
  CLEANUP=false
  MEASURE_COST=true
  MEASURE_COST_TAIL_SECONDS=120
  MEASURE_COST_DELAY_SECONDS=600       (CloudWatch AWS/Logs lags ~10m)
  MEASURE_COST_REGION=us-east-1
  MEASURE_COST_EXTRA_ARGS=""
EOF_USAGE
}

is_positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

is_non_negative_integer() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

is_boolean() {
  [[ "$1" == "true" || "$1" == "false" ]]
}

require_positive_integer() {
  local name="$1"
  local value="$2"

  if ! is_positive_integer "${value}"; then
    echo "${name} must be a positive integer, got: ${value}" >&2
    exit 1
  fi
}

require_non_negative_integer() {
  local name="$1"
  local value="$2"

  if ! is_non_negative_integer "${value}"; then
    echo "${name} must be a non-negative integer, got: ${value}" >&2
    exit 1
  fi
}

require_boolean() {
  local name="$1"
  local value="$2"

  if ! is_boolean "${value}"; then
    echo "${name} must be true or false, got: ${value}" >&2
    exit 1
  fi
}

ensure_valid_job_name() {
  local job_name="$1"

  if (( ${#job_name} > 63 )); then
    echo "Generated job name is too long for Kubernetes: ${job_name}" >&2
    exit 1
  fi
}

KUBECTL_APPLY_RETRIES="${KUBECTL_APPLY_RETRIES:-8}"
KUBECTL_APPLY_RETRY_BASE_MS="${KUBECTL_APPLY_RETRY_BASE_MS:-150}"

kubectl_apply_retry() {
  local attempt=1
  local stderr_file
  stderr_file="$(mktemp)"
  local input
  input="$(cat)"

  while :; do
    if printf '%s' "${input}" | kubectl apply "$@" 2>"${stderr_file}"; then
      rm -f "${stderr_file}"
      return 0
    fi

    local err
    err="$(cat "${stderr_file}")"
    if (( attempt >= KUBECTL_APPLY_RETRIES )) \
       || ! grep -qE 'TransactionConflict|TransactionCanceledException|Conflict|the object has been modified|try again|i/o timeout|connection reset|TooManyRequests|429' <<< "${err}"; then
      echo "${err}" >&2
      rm -f "${stderr_file}"
      return 1
    fi

    local backoff_ms=$(( KUBECTL_APPLY_RETRY_BASE_MS * (1 << (attempt - 1)) ))
    if (( backoff_ms > 5000 )); then backoff_ms=5000; fi
    local jitter_ms=$(( RANDOM % 100 ))
    sleep "$(awk -v b="${backoff_ms}" -v j="${jitter_ms}" 'BEGIN { printf "%.3f", (b + j) / 1000 }')"
    attempt=$((attempt + 1))
  done
}

print_status() {
  echo
  echo "[*] Jobs in ${NS} (selector ${JOB_SELECTOR}):"
  kubectl -n "${NS}" get jobs -l "${JOB_SELECTOR}" || true
  echo
  echo "[*] Pods in ${NS} (selector ${JOB_SELECTOR}):"
  kubectl -n "${NS}" get pods -l "${JOB_SELECTOR}" -o wide || true
}

create_job() {
  local job_index="$1"
  local job_name="$2"

  cat <<EOF_JOB | kubectl_apply_retry -n "${NS}" -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: ${job_name}
  labels:
    app: ${APP_LABEL}
    run: ${RUN_LABEL}
spec:
  completions: ${JOB_COMPLETIONS}
  parallelism: ${JOB_PARALLELISM}
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
      containers:
      - name: worker
        image: ${IMAGE}
        imagePullPolicy: ${IMAGE_PULL_POLICY}
        command:
        - /bin/sh
        - -c
        - |
          set -eu
          job_index="${job_index}"
          workload_sleep_seconds="${WORKLOAD_SLEEP_SECONDS}"
          workdir="/tmp/work-${job_index}-$$"
          mkdir -p "\${workdir}"
          awk -v items="${WORK_ITEMS}" -v seed="${job_index}" 'BEGIN {
            for (i = 1; i <= items; i++) {
              value = (seed * 7919 + i * 104729) % 100000
              printf "%05d\n", value
            }
          }' > "\${workdir}/numbers.txt"
          sort -n "\${workdir}/numbers.txt" > "\${workdir}/numbers.sorted.txt"
          awk 'BEGIN { sum = 0 }
            {
              sum += \$1
              if (NR == 1 || \$1 < min) { min = \$1 }
              if (NR == 1 || \$1 > max) { max = \$1 }
            }
            END {
              printf "count=%d\nsum=%d\nmin=%d\nmax=%d\n", NR, sum, min, max
            }' "\${workdir}/numbers.sorted.txt" > "\${workdir}/summary.txt"
          cksum "\${workdir}/numbers.sorted.txt" >> "\${workdir}/summary.txt"
          echo "job_index=\${job_index} pod_name=\$(hostname) started_at=\$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
          cat "\${workdir}/summary.txt"
          sleep "\${workload_sleep_seconds}"
        resources:
          requests:
            cpu: "${POD_CPU_REQUEST}"
            memory: "${POD_MEMORY_REQUEST}"
EOF_JOB
}

submit_jobs() {
  local jobs_to_submit="$1"
  local submitted_jobs_ref_name="$2"
  local -n submitted_jobs_ref="${submitted_jobs_ref_name}"
  local i=""
  local job_name=""
  local job_suffix=""

  for ((i = 1; i <= jobs_to_submit; i++)); do
    submitted_jobs_ref=$((submitted_jobs_ref + 1))
    job_suffix="$(printf '%06d' "${submitted_jobs_ref}")"
    job_name="${JOB_BASENAME}-${RUN_ID}-${job_suffix}"
    ensure_valid_job_name "${job_name}"

    echo "[*] ($(date -u '+%Y-%m-%dT%H:%M:%SZ')) Creating job ${submitted_jobs_ref}: ${job_name}"
    create_job "${submitted_jobs_ref}" "${job_name}"
  done
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_positive_integer "TEST_DURATION_SECONDS" "${TEST_DURATION_SECONDS}"
require_positive_integer "SUBMISSION_INTERVAL_SECONDS" "${SUBMISSION_INTERVAL_SECONDS}"
require_positive_integer "JOBS_PER_INTERVAL" "${JOBS_PER_INTERVAL}"
require_positive_integer "JOB_COMPLETIONS" "${JOB_COMPLETIONS}"
require_positive_integer "JOB_PARALLELISM" "${JOB_PARALLELISM}"
require_positive_integer "WORK_ITEMS" "${WORK_ITEMS}"
require_non_negative_integer "WORKLOAD_SLEEP_SECONDS" "${WORKLOAD_SLEEP_SECONDS}"
require_positive_integer "JOB_TTL_SECONDS" "${JOB_TTL_SECONDS}"
require_boolean "WAIT_FOR_COMPLETION" "${WAIT_FOR_COMPLETION}"
require_boolean "CLEANUP" "${CLEANUP}"
require_boolean "MEASURE_COST" "${MEASURE_COST}"
require_non_negative_integer "MEASURE_COST_TAIL_SECONDS" "${MEASURE_COST_TAIL_SECONDS}"
require_non_negative_integer "MEASURE_COST_DELAY_SECONDS" "${MEASURE_COST_DELAY_SECONDS}"

if (( ${#APP_LABEL} > 63 )); then
  echo "APP_LABEL must be 63 characters or fewer, got: ${APP_LABEL}" >&2
  exit 1
fi

if (( ${#RUN_LABEL} > 63 )); then
  echo "RUN_LABEL must be 63 characters or fewer, got: ${RUN_LABEL}" >&2
  exit 1
fi

if (( ${#NS} > 63 )); then
  echo "NS must be 63 characters or fewer, got: ${NS}" >&2
  exit 1
fi

trap 'echo; echo "[!] Interrupted. Current status:"; print_status; exit 130' INT TERM

start_epoch="$(date +%s)"
end_epoch=$((start_epoch + TEST_DURATION_SECONDS))
START_ISO="$(date -u -d "@${start_epoch}" '+%Y-%m-%dT%H:%M:%SZ')"
submitted_jobs=0
iteration=0

expected_intervals=$(( (TEST_DURATION_SECONDS + SUBMISSION_INTERVAL_SECONDS - 1) / SUBMISSION_INTERVAL_SECONDS ))
expected_jobs=$(( expected_intervals * JOBS_PER_INTERVAL ))
expected_pods=$(( expected_jobs * JOB_COMPLETIONS ))
steady_state_pods=$(( ((WORKLOAD_SLEEP_SECONDS + SUBMISSION_INTERVAL_SECONDS - 1) / SUBMISSION_INTERVAL_SECONDS) * JOBS_PER_INTERVAL * JOB_PARALLELISM ))

echo "[*] Ensuring namespace ${NS} exists"
kubectl create namespace "${NS}" --dry-run=client -o yaml | kubectl_apply_retry -f -

echo "[*] Starting steady-state workload run"
echo "[*] Namespace: ${NS}"
echo "[*] Selector: ${JOB_SELECTOR}"
echo "[*] Duration: ${TEST_DURATION_SECONDS}s"
echo "[*] Submission interval: ${SUBMISSION_INTERVAL_SECONDS}s (${JOBS_PER_INTERVAL} job(s) per interval, ~${expected_jobs} jobs total)"
echo "[*] Per-job pods: completions=${JOB_COMPLETIONS} parallelism=${JOB_PARALLELISM} (~${JOB_COMPLETIONS} pod(s) per completed job)"
echo "[*] Expected pod creations: ~${expected_pods} total"
echo "[*] Estimated steady-state active pods: ~${steady_state_pods}"
echo "[*] Workload: generate ${WORK_ITEMS} numbers, sort, summarize, sleep ${WORKLOAD_SLEEP_SECONDS}s"
echo "[*] Job ttlSecondsAfterFinished: ${JOB_TTL_SECONDS}s"

while :; do
  now_epoch="$(date +%s)"
  if (( now_epoch >= end_epoch )); then
    break
  fi

  iteration=$((iteration + 1))
  echo "[*] ($(date -u '+%Y-%m-%dT%H:%M:%SZ')) iteration=${iteration} submitting=${JOBS_PER_INTERVAL}"
  submit_jobs "${JOBS_PER_INTERVAL}" submitted_jobs

  now_epoch="$(date +%s)"
  remaining_seconds=$((end_epoch - now_epoch))
  if (( remaining_seconds <= 0 )); then
    break
  fi

  sleep_seconds="${SUBMISSION_INTERVAL_SECONDS}"
  if (( remaining_seconds < sleep_seconds )); then
    sleep_seconds="${remaining_seconds}"
  fi

  sleep "${sleep_seconds}"
done

echo
echo "[*] Finished submission loop after ${TEST_DURATION_SECONDS}s"
echo "[*] Submitted ${submitted_jobs} jobs total"
echo "[*] Expected pod creations from submitted jobs: $((submitted_jobs * JOB_COMPLETIONS))"
print_status

if [[ "${WAIT_FOR_COMPLETION}" == "true" ]]; then
  echo
  echo "[*] Waiting for submitted jobs in ${NS} to complete..."
  kubectl -n "${NS}" wait --for=condition=complete job -l "${JOB_SELECTOR}" --timeout="${WAIT_TIMEOUT}"
  print_status
fi

if [[ "${CLEANUP}" == "true" ]]; then
  echo
  echo "[*] Cleaning up jobs in ${NS} (selector ${JOB_SELECTOR})..."
  kubectl -n "${NS}" delete jobs -l "${JOB_SELECTOR}" --wait=false --ignore-not-found=true
else
  echo
  echo "[*] Leaving resources in place. Inspect them with:"
  echo "kubectl -n ${NS} get jobs -l ${JOB_SELECTOR}"
  echo "kubectl -n ${NS} get pods -l ${JOB_SELECTOR} -o wide"
fi

if [[ "${MEASURE_COST}" == "true" ]]; then
  if [[ ! -f "${MEASURE_COST_SCRIPT}" ]]; then
    echo
    echo "[!] MEASURE_COST=true but script not found: ${MEASURE_COST_SCRIPT}" >&2
  else
    if (( MEASURE_COST_TAIL_SECONDS > 0 )); then
      echo
      echo "[*] Draining ${MEASURE_COST_TAIL_SECONDS}s before closing the cost window (lets cleanup/cascade settle)"
      sleep "${MEASURE_COST_TAIL_SECONDS}"
    fi
    END_ISO="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "[*] Cost window: ${START_ISO}  ->  ${END_ISO}"

    if (( MEASURE_COST_DELAY_SECONDS > 0 )); then
      echo "[*] Waiting ${MEASURE_COST_DELAY_SECONDS}s for CloudWatch metrics to publish (AWS/Logs lags ~10m; AWS/Lambda+DynamoDB+SQS land in ~1-3m)"
      sleep "${MEASURE_COST_DELAY_SECONDS}"
    fi

    echo
    echo "[*] Running measure_cost.py for window [${START_ISO}, ${END_ISO}] in region ${MEASURE_COST_REGION}"
    # shellcheck disable=SC2086
    "${MEASURE_COST_PYTHON}" "${MEASURE_COST_SCRIPT}" \
      --start "${START_ISO}" \
      --end "${END_ISO}" \
      --region "${MEASURE_COST_REGION}" \
      ${MEASURE_COST_EXTRA_ARGS} || echo "[!] measure_cost.py exited non-zero"
  fi
fi