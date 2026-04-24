#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_LOCAL_DIR="${REPO_LOCAL_DIR:-$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel 2>/dev/null || (cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd))}"
OUT_DIR="${OUT_DIR:-${REPO_LOCAL_DIR}/_ec2_out}"

export KUBECONFIG="${KUBECONFIG:-${OUT_DIR}/admin.public.conf}"
NS="${NS:-hello-test}"
JOB_BASENAME="${JOB_BASENAME:-scheduler-saturation-test}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%d%H%M%S)}"
APP_LABEL="${APP_LABEL:-scheduler-saturation-test}"
RUN_LABEL="${RUN_LABEL:-${JOB_BASENAME}-${RUN_ID}}"
TEST_DURATION_SECONDS="${TEST_DURATION_SECONDS:-3600}"
SUBMISSION_INTERVAL_SECONDS="${SUBMISSION_INTERVAL_SECONDS:-1}"
MAX_JOBS_PER_INTERVAL="${MAX_JOBS_PER_INTERVAL:-100}"
TARGET_PENDING_PODS="${TARGET_PENDING_PODS:-250}"
TARGET_INFLIGHT_PODS="${TARGET_INFLIGHT_PODS:-500}"
WORK_ITEMS="${WORK_ITEMS:-4000}"
WORKLOAD_SLEEP_SECONDS="${WORKLOAD_SLEEP_SECONDS:-300}"
POD_CPU_REQUEST="${POD_CPU_REQUEST:-150m}"
POD_MEMORY_REQUEST="${POD_MEMORY_REQUEST:-128Mi}"
JOB_TTL_SECONDS="${JOB_TTL_SECONDS:-7200}"
WAIT_FOR_COMPLETION="${WAIT_FOR_COMPLETION:-false}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-90m}"
CLEANUP="${CLEANUP:-false}"
IMAGE="${IMAGE:-busybox:1.36}"
IMAGE_PULL_POLICY="${IMAGE_PULL_POLICY:-IfNotPresent}"
JOB_SELECTOR="app=${APP_LABEL},run=${RUN_LABEL}"

usage() {
  cat <<'EOF_USAGE'
Usage: ./scripts/test_schedule_minutely.sh

This script continuously tops up one-pod Jobs so the scheduler always has fresh pods to place.
By default it runs for one hour and tries to maintain both:
  - unscheduled pending pods (pods still waiting for a node assignment)
  - inflight pods (all non-terminal pods)

Important design note:
  - Each Job creates exactly one pod.
  - This keeps the control loop stable: one submitted Job == one additional pod.
  - That avoids the overshoot you get when a single Job fans out into many pods.

Environment overrides:
  NS=hello-test
  TEST_DURATION_SECONDS=3600
  SUBMISSION_INTERVAL_SECONDS=1
  MAX_JOBS_PER_INTERVAL=100
  TARGET_PENDING_PODS=250
  TARGET_INFLIGHT_PODS=500
  WORK_ITEMS=4000
  WORKLOAD_SLEEP_SECONDS=300
  POD_CPU_REQUEST=150m
  POD_MEMORY_REQUEST=128Mi
  JOB_TTL_SECONDS=7200
  WAIT_FOR_COMPLETION=false
  WAIT_TIMEOUT=90m
  CLEANUP=false
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

print_status() {
  echo
  echo "[*] Jobs for selector ${JOB_SELECTOR}:"
  kubectl -n "${NS}" get jobs -l "${JOB_SELECTOR}" || true
  echo
  echo "[*] Pods for selector ${JOB_SELECTOR}:"
  kubectl -n "${NS}" get pods -l "${JOB_SELECTOR}" -o wide || true
}

count_pods() {
  local pod_rows=""

  pod_rows="$(kubectl -n "${NS}" get pods -l "${JOB_SELECTOR}" \
    -o jsonpath='{range .items[*]}{.status.phase}{","}{.spec.nodeName}{"\n"}{end}' 2>/dev/null || true)"

  awk -F, '
    BEGIN {
      unscheduled_pending = 0
      inflight = 0
    }
    NF {
      phase = $1
      node = $2

      if (phase == "Pending" && node == "") {
        unscheduled_pending++
      }

      if (phase != "Succeeded" && phase != "Failed") {
        inflight++
      }
    }
    END {
      printf "%d %d\n", unscheduled_pending, inflight
    }
  ' <<< "${pod_rows}"
}

jobs_needed_for_deficit() {
  local deficit="$1"

  if (( deficit <= 0 )); then
    echo 0
  else
    echo "${deficit}"
  fi
}

create_job() {
  local job_index="$1"
  local job_name="$2"

  cat <<EOF_JOB | kubectl apply -n "${NS}" -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: ${job_name}
  labels:
    app: ${APP_LABEL}
    run: ${RUN_LABEL}
spec:
  completions: 1
  parallelism: 1
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
              sum += $1
              if (NR == 1 || $1 < min) { min = $1 }
              if (NR == 1 || $1 > max) { max = $1 }
            }
            END {
              printf "count=%d\nsum=%d\nmin=%d\nmax=%d\n", NR, sum, min, max
            }' "\${workdir}/numbers.sorted.txt" > "\${workdir}/summary.txt"
          cksum "\${workdir}/numbers.sorted.txt" >> "\${workdir}/summary.txt"
          echo "job_index=\${job_index} pod_name=$(hostname) started_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
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
require_positive_integer "MAX_JOBS_PER_INTERVAL" "${MAX_JOBS_PER_INTERVAL}"
require_non_negative_integer "TARGET_PENDING_PODS" "${TARGET_PENDING_PODS}"
require_non_negative_integer "TARGET_INFLIGHT_PODS" "${TARGET_INFLIGHT_PODS}"
require_positive_integer "WORK_ITEMS" "${WORK_ITEMS}"
require_non_negative_integer "WORKLOAD_SLEEP_SECONDS" "${WORKLOAD_SLEEP_SECONDS}"
require_positive_integer "JOB_TTL_SECONDS" "${JOB_TTL_SECONDS}"
require_boolean "WAIT_FOR_COMPLETION" "${WAIT_FOR_COMPLETION}"
require_boolean "CLEANUP" "${CLEANUP}"

if (( TARGET_PENDING_PODS > TARGET_INFLIGHT_PODS )); then
  echo "TARGET_PENDING_PODS cannot be greater than TARGET_INFLIGHT_PODS" >&2
  exit 1
fi

if (( ${#APP_LABEL} > 63 )); then
  echo "APP_LABEL must be 63 characters or fewer, got: ${APP_LABEL}" >&2
  exit 1
fi

if (( ${#RUN_LABEL} > 63 )); then
  echo "RUN_LABEL must be 63 characters or fewer, got: ${RUN_LABEL}" >&2
  exit 1
fi

trap 'echo; echo "[!] Interrupted. Current status:"; print_status; exit 130' INT TERM

kubectl create namespace "${NS}" --dry-run=client -o yaml | kubectl apply -f -

echo "[*] Starting continuous scheduler saturation run"
echo "[*] Namespace: ${NS}"
echo "[*] Selector: ${JOB_SELECTOR}"
echo "[*] Duration: ${TEST_DURATION_SECONDS}s"
echo "[*] Submission interval: ${SUBMISSION_INTERVAL_SECONDS}s"
echo "[*] Max jobs per interval: ${MAX_JOBS_PER_INTERVAL}"
echo "[*] Per-job pods: completions=1 parallelism=1"
echo "[*] Target backlog: unscheduled_pending=${TARGET_PENDING_PODS} inflight=${TARGET_INFLIGHT_PODS}"
echo "[*] Workload: generate ${WORK_ITEMS} numbers, sort them, compute summary, sleep ${WORKLOAD_SLEEP_SECONDS}s"

start_epoch="$(date +%s)"
end_epoch=$((start_epoch + TEST_DURATION_SECONDS))
submitted_jobs=0
iteration=0

while :; do
  now_epoch="$(date +%s)"
  if (( now_epoch >= end_epoch )); then
    break
  fi

  iteration=$((iteration + 1))
  read -r unscheduled_pending_pods inflight_pods < <(count_pods)

  pending_deficit=$((TARGET_PENDING_PODS - unscheduled_pending_pods))
  inflight_deficit=$((TARGET_INFLIGHT_PODS - inflight_pods))

  jobs_for_pending="$(jobs_needed_for_deficit "${pending_deficit}")"
  jobs_for_inflight="$(jobs_needed_for_deficit "${inflight_deficit}")"
  jobs_to_submit="${jobs_for_pending}"
  if (( jobs_for_inflight > jobs_to_submit )); then
    jobs_to_submit="${jobs_for_inflight}"
  fi
  if (( jobs_to_submit > MAX_JOBS_PER_INTERVAL )); then
    jobs_to_submit="${MAX_JOBS_PER_INTERVAL}"
  fi

  echo "[*] ($(date -u '+%Y-%m-%dT%H:%M:%SZ')) iteration=${iteration} unscheduled_pending=${unscheduled_pending_pods} inflight=${inflight_pods} pending_deficit=${pending_deficit} inflight_deficit=${inflight_deficit} jobs_to_submit=${jobs_to_submit}"

  if (( jobs_to_submit > 0 )); then
    submit_jobs "${jobs_to_submit}" submitted_jobs
  fi

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
print_status

if [[ "${WAIT_FOR_COMPLETION}" == "true" ]]; then
  echo
  echo "[*] Waiting for submitted jobs to complete..."
  kubectl -n "${NS}" wait --for=condition=complete job -l "${JOB_SELECTOR}" --timeout="${WAIT_TIMEOUT}"
  print_status
fi

if [[ "${CLEANUP}" == "true" ]]; then
  echo
  echo "[*] Cleaning up jobs for this run..."
  kubectl -n "${NS}" delete jobs -l "${JOB_SELECTOR}" --ignore-not-found=true
else
  echo
  echo "[*] Leaving jobs in place. Inspect them with:"
  echo "kubectl -n ${NS} get jobs -l ${JOB_SELECTOR}"
  echo "kubectl -n ${NS} get pods -l ${JOB_SELECTOR} -o wide"
fi
