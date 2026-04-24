#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_LOCAL_DIR="${REPO_LOCAL_DIR:-$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel 2>/dev/null || (cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd))}"
OUT_DIR="${OUT_DIR:-${REPO_LOCAL_DIR}/_ec2_out}"
CLUSTER_ENV_FILE="${CLUSTER_ENV_FILE:-${OUT_DIR}/cluster.env}"

if [[ -f "${CLUSTER_ENV_FILE}" ]]; then
  # shellcheck source=/dev/null
  source "${CLUSTER_ENV_FILE}"
fi

export KUBECONFIG="${KUBECONFIG:-${OUT_DIR}/admin.public.conf}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%d%H%M%S)}"
TEST_SCRIPT="${TEST_SCRIPT:-${SCRIPT_DIR}/test_schedule_minutely.sh}"
TEST_DURATION_SECONDS="${TEST_DURATION_SECONDS:-3600}"
PROFILE_SECONDS="${PROFILE_SECONDS:-${TEST_DURATION_SECONDS}}"
SAMPLE_INTERVAL_SECONDS="${SAMPLE_INTERVAL_SECONDS:-5}"
SUBMISSION_INTERVAL_SECONDS="${SUBMISSION_INTERVAL_SECONDS:-1}"
MAX_JOBS_PER_INTERVAL="${MAX_JOBS_PER_INTERVAL:-100}"
TARGET_PENDING_PODS="${TARGET_PENDING_PODS:-250}"
TARGET_INFLIGHT_PODS="${TARGET_INFLIGHT_PODS:-500}"
KCM_PPROF_PORT="${KCM_PPROF_PORT:-10257}"
KCM_CONTROLLER_FOCUS_REGEX="${KCM_CONTROLLER_FOCUS_REGEX:-k8s\.io/kubernetes/pkg/controller/(job|ttlafterfinished|namespace|podgc)}"
GO_BINARY="${GO_BINARY:-go}"
MONITOR_OUT_DIR="${MONITOR_OUT_DIR:-${OUT_DIR}/serverful/${RUN_ID}}"
PROCESS_SAMPLES_FILE="${PROCESS_SAMPLES_FILE:-${MONITOR_OUT_DIR}/process_cpu_samples.csv}"
PROCESS_SUMMARY_FILE="${PROCESS_SUMMARY_FILE:-${MONITOR_OUT_DIR}/process_cpu_summary.tsv}"
TEST_LOG_FILE="${TEST_LOG_FILE:-${MONITOR_OUT_DIR}/test_schedule_minutely.log}"
MONITOR_LOG_FILE="${MONITOR_LOG_FILE:-${MONITOR_OUT_DIR}/process_cpu_monitor.log}"
PPROF_LOG_FILE="${PPROF_LOG_FILE:-${MONITOR_OUT_DIR}/controller_manager_pprof.log}"
KCM_PPROF_FILE="${KCM_PPROF_FILE:-${MONITOR_OUT_DIR}/kube-controller-manager.pprof}"
KCM_PPROF_TOP_FILE="${KCM_PPROF_TOP_FILE:-${MONITOR_OUT_DIR}/kube-controller-manager.top.txt}"
KCM_PPROF_FOCUSED_TOP_FILE="${KCM_PPROF_FOCUSED_TOP_FILE:-${MONITOR_OUT_DIR}/kube-controller-manager.focused.top.txt}"
SUMMARY_FILE="${SUMMARY_FILE:-${MONITOR_OUT_DIR}/serverful_cpu_summary.tsv}"
METADATA_FILE="${METADATA_FILE:-${MONITOR_OUT_DIR}/metadata.env}"
STOP_FILE="${MONITOR_OUT_DIR}/.stop"
SSH_USER="${SSH_USER:-ubuntu}"
SSH_HOST="${SSH_HOST:-${CONTROL_PUB:-}}"
SSH_IDENTITY_FILE="${SSH_IDENTITY_FILE:-${IDENTITY_FILE:-}}"
SOCK_DIR="${SOCK_DIR:-${REPO_LOCAL_DIR}/_ssh_mux}"
PPROF_STARTUP_GRACE_SECONDS="${PPROF_STARTUP_GRACE_SECONDS:-3}"
PPROF_START_RETRY_SECONDS="${PPROF_START_RETRY_SECONDS:-10}"
PPROF_START_TIMEOUT_SECONDS="${PPROF_START_TIMEOUT_SECONDS:-120}"
REQUIRE_CONTROLLER_MANAGER_PPROF="${REQUIRE_CONTROLLER_MANAGER_PPROF:-true}"

MONITOR_PID=""
PPROF_PID=""
MONITOR_STARTED="false"
PPROF_STARTED="false"
FINALIZED="false"
PPROF_EXIT_CODE=0
REMOTE_CLK_TCK=""
REMOTE_CPU_COUNT=""
STARTED_AT_UTC=""
TEST_EXIT_CODE=0
SCHEDULER_AVG_CPU_PERCENT="NA"
CONTROLLER_MANAGER_PROCESS_AVG_CPU_PERCENT="NA"
CONTROLLER_MANAGER_WHOLE_CPU_PERCENT="NA"
CONTROLLER_MANAGER_WHOLE_SOURCE="unavailable"
CONTROLLER_MANAGER_WHOLE_ARTIFACT=""
TARGET_CONTROLLERS_COMBINED_CPU_PERCENT="NA"
TARGET_CONTROLLERS_COMBINED_SOURCE="unavailable"
ACTIVE_PPROF_TMP_FILE=""
ACTIVE_PPROF_START_ATTEMPT=""

usage() {
  cat <<'EOF_USAGE'
Usage: ./scripts/test_schedule_serverful.sh

This wrapper:
  1. starts process-level CPU sampling for kube-scheduler and kube-controller-manager
  2. acquires an exclusive kube-controller-manager CPU pprof profile for the run duration
  3. runs ./scripts/test_schedule_minutely.sh
  4. reports:
     - scheduler average CPU usage
     - controller-manager CPU usage as a whole
     - combined CPU usage of the job, ttlafterfinished, podgc, and namespace controllers

Important:
  - CPU percentage is reported relative to one vCPU.
  - 100% means one full core was saturated over the measurement interval.
  - By default the script requires a valid controller-manager pprof capture.
    If pprof is already in use or invalid, the run fails before the workload starts.
  - Set REQUIRE_CONTROLLER_MANAGER_PPROF=false only if you explicitly want a best-effort run.

Environment overrides:
  RUN_ID=20260423093000
  TEST_SCRIPT=./scripts/test_schedule_minutely.sh
  TEST_DURATION_SECONDS=3600
  PROFILE_SECONDS=3600
  SAMPLE_INTERVAL_SECONDS=5
  SUBMISSION_INTERVAL_SECONDS=1
  MAX_JOBS_PER_INTERVAL=100
  TARGET_PENDING_PODS=250
  TARGET_INFLIGHT_PODS=500
  KCM_PPROF_PORT=10257
  PPROF_STARTUP_GRACE_SECONDS=3
  PPROF_START_RETRY_SECONDS=10
  PPROF_START_TIMEOUT_SECONDS=120
  REQUIRE_CONTROLLER_MANAGER_PPROF=true
  MONITOR_OUT_DIR=./_ec2_out/serverful/<RUN_ID>
  SSH_USER=ubuntu
  SSH_HOST=<control-plane-public-ip>
  SSH_IDENTITY_FILE=~/.ssh/my-key.pem
EOF_USAGE
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

is_positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
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

require_boolean() {
  local name="$1"
  local value="$2"

  if ! is_boolean "${value}"; then
    echo "${name} must be true or false, got: ${value}" >&2
    exit 1
  fi
}

ssh_do() {
  ssh "${SSH_OPTS[@]}" "${SSH_USER}@${SSH_HOST}" "$@"
}

prime_ssh_connection() {
  ssh -fN "${SSH_OPTS[@]}" "${SSH_USER}@${SSH_HOST}" || true
}

close_ssh_connection() {
  ssh -O exit "${SSH_OPTS[@]}" "${SSH_USER}@${SSH_HOST}" >/dev/null 2>&1 || true
}

fetch_remote_context() {
  local remote_context

  remote_context="$(ssh_do 'printf "CLK_TCK=%s\nNPROC=%s\n" "$(getconf CLK_TCK)" "$(nproc)"')"
  REMOTE_CLK_TCK="$(printf '%s\n' "${remote_context}" | awk -F= '$1 == "CLK_TCK" { print $2; exit }')"
  REMOTE_CPU_COUNT="$(printf '%s\n' "${remote_context}" | awk -F= '$1 == "NPROC" { print $2; exit }')"

  if ! is_positive_integer "${REMOTE_CLK_TCK}"; then
    echo "Failed to read remote CLK_TCK from ${SSH_HOST}" >&2
    exit 1
  fi

  if ! is_positive_integer "${REMOTE_CPU_COUNT}"; then
    echo "Failed to read remote CPU count from ${SSH_HOST}" >&2
    exit 1
  fi
}

capture_remote_snapshot() {
  ssh "${SSH_OPTS[@]}" "${SSH_USER}@${SSH_HOST}" 'bash -s' <<'EOF_REMOTE'
find_pid() {
  local component="$1"
  ps -eo pid=,args= | awk -v component="${component}" '$2 == component { print $1; exit }'
}

emit_component() {
  local component="$1"
  local pid=""
  local ticks=""

  pid="$(find_pid "${component}")"
  if [[ -n "${pid}" && -r "/proc/${pid}/stat" ]]; then
    ticks="$(awk '{ print $14 + $15 }' "/proc/${pid}/stat")"
  fi

  printf '%s,%s,%s\n' "${component}" "${pid}" "${ticks}"
}

emit_component "kube-scheduler"
emit_component "kube-controller-manager"
EOF_REMOTE
}

assert_components_present() {
  local snapshot
  local missing_components=()

  snapshot="$(capture_remote_snapshot)"

  while IFS=, read -r component pid _ticks; do
    if [[ -z "${pid}" ]]; then
      missing_components+=("${component}")
    fi
  done <<< "${snapshot}"

  if (( ${#missing_components[@]} > 0 )); then
    echo "Missing expected control-plane process(es) on ${SSH_HOST}: ${missing_components[*]}" >&2
    echo "This wrapper expects the built-in kube-scheduler and kube-controller-manager to be running." >&2
    exit 1
  fi
}

write_metadata() {
  cat > "${METADATA_FILE}" <<EOF_META
RUN_ID=${RUN_ID}
STARTED_AT_UTC=${STARTED_AT_UTC}
TEST_SCRIPT=${TEST_SCRIPT}
TEST_DURATION_SECONDS=${TEST_DURATION_SECONDS}
PROFILE_SECONDS=${PROFILE_SECONDS}
SAMPLE_INTERVAL_SECONDS=${SAMPLE_INTERVAL_SECONDS}
SUBMISSION_INTERVAL_SECONDS=${SUBMISSION_INTERVAL_SECONDS}
MAX_JOBS_PER_INTERVAL=${MAX_JOBS_PER_INTERVAL}
TARGET_PENDING_PODS=${TARGET_PENDING_PODS}
TARGET_INFLIGHT_PODS=${TARGET_INFLIGHT_PODS}
SSH_USER=${SSH_USER}
SSH_HOST=${SSH_HOST}
SSH_IDENTITY_FILE=${SSH_IDENTITY_FILE}
REMOTE_CLK_TCK=${REMOTE_CLK_TCK}
REMOTE_CPU_COUNT=${REMOTE_CPU_COUNT}
KCM_PPROF_PORT=${KCM_PPROF_PORT}
KCM_CONTROLLER_FOCUS_REGEX=${KCM_CONTROLLER_FOCUS_REGEX}
PROCESS_SAMPLES_FILE=${PROCESS_SAMPLES_FILE}
PROCESS_SUMMARY_FILE=${PROCESS_SUMMARY_FILE}
KCM_PPROF_FILE=${KCM_PPROF_FILE}
KCM_PPROF_TOP_FILE=${KCM_PPROF_TOP_FILE}
KCM_PPROF_FOCUSED_TOP_FILE=${KCM_PPROF_FOCUSED_TOP_FILE}
SUMMARY_FILE=${SUMMARY_FILE}
TEST_LOG_FILE=${TEST_LOG_FILE}
MONITOR_LOG_FILE=${MONITOR_LOG_FILE}
PPROF_LOG_FILE=${PPROF_LOG_FILE}
PPROF_STARTUP_GRACE_SECONDS=${PPROF_STARTUP_GRACE_SECONDS}
PPROF_START_RETRY_SECONDS=${PPROF_START_RETRY_SECONDS}
PPROF_START_TIMEOUT_SECONDS=${PPROF_START_TIMEOUT_SECONDS}
REQUIRE_CONTROLLER_MANAGER_PPROF=${REQUIRE_CONTROLLER_MANAGER_PPROF}
EOF_META
}

monitor_process_loop() {
  declare -A prev_pid=()
  declare -A prev_ticks=()
  declare -A prev_time_ns=()

  local sample_utc=""
  local sample_time_ns=""
  local start_time_ns=""
  local elapsed_seconds=""
  local snapshot=""
  local component=""
  local pid=""
  local ticks=""
  local delta_ticks=0
  local delta_ns=0
  local cpu_percent=""
  local previous_ticks=""
  local previous_time_ns=""

  printf 'timestamp_utc,elapsed_seconds,component,pid,cpu_ticks,cpu_percent\n' > "${PROCESS_SAMPLES_FILE}"

  while [[ ! -f "${STOP_FILE}" ]]; do
    sample_time_ns="$(date +%s%N)"
    sample_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    if [[ -z "${start_time_ns}" ]]; then
      start_time_ns="${sample_time_ns}"
    fi

    elapsed_seconds="$(awk -v now="${sample_time_ns}" -v start="${start_time_ns}" 'BEGIN { printf "%.3f", (now - start) / 1000000000 }')"

    if ! snapshot="$(capture_remote_snapshot)"; then
      printf '[%s] Failed to capture process CPU snapshot from %s\n' "${sample_utc}" "${SSH_HOST}" >> "${MONITOR_LOG_FILE}"
      sleep "${SAMPLE_INTERVAL_SECONDS}"
      continue
    fi

    while IFS=, read -r component pid ticks; do
      cpu_percent=""

      if [[ -n "${pid}" && -n "${ticks}" && -n "${prev_pid[${component}]:-}" && "${prev_pid[${component}]}" == "${pid}" ]]; then
        previous_ticks="${prev_ticks[${component}]}"
        previous_time_ns="${prev_time_ns[${component}]}"
        delta_ticks=$((ticks - previous_ticks))
        delta_ns=$((sample_time_ns - previous_time_ns))

        if (( delta_ticks >= 0 && delta_ns > 0 )); then
          cpu_percent="$(awk -v dticks="${delta_ticks}" -v dns="${delta_ns}" -v clk="${REMOTE_CLK_TCK}" 'BEGIN { printf "%.4f", ((dticks / clk) / (dns / 1000000000)) * 100 }')"
        fi
      fi

      printf '%s,%s,%s,%s,%s,%s\n' "${sample_utc}" "${elapsed_seconds}" "${component}" "${pid}" "${ticks}" "${cpu_percent}" >> "${PROCESS_SAMPLES_FILE}"

      if [[ -n "${pid}" && -n "${ticks}" ]]; then
        prev_pid["${component}"]="${pid}"
        prev_ticks["${component}"]="${ticks}"
        prev_time_ns["${component}"]="${sample_time_ns}"
      else
        unset "prev_pid[${component}]"
        unset "prev_ticks[${component}]"
        unset "prev_time_ns[${component}]"
      fi
    done <<< "${snapshot}"

    sleep "${SAMPLE_INTERVAL_SECONDS}"
  done
}

start_process_monitor() {
  mkdir -p "${MONITOR_OUT_DIR}" "${SOCK_DIR}"
  : > "${MONITOR_LOG_FILE}"
  rm -f "${STOP_FILE}"

  prime_ssh_connection
  fetch_remote_context
  assert_components_present

  STARTED_AT_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  write_metadata

  monitor_process_loop &
  MONITOR_PID="$!"
  MONITOR_STARTED="true"
}

stop_process_monitor() {
  if [[ "${MONITOR_STARTED}" != "true" ]]; then
    return 0
  fi

  touch "${STOP_FILE}"
  if [[ -n "${MONITOR_PID}" ]]; then
    wait "${MONITOR_PID}" || true
  fi
}

capture_controller_manager_pprof() {
  ssh "${SSH_OPTS[@]}" "${SSH_USER}@${SSH_HOST}" 'bash -s' -- "${KCM_PPROF_PORT}" "${PROFILE_SECONDS}" <<'EOF_REMOTE'
set -euo pipefail

pprof_port="${1:?pprof port}"
profile_seconds="${2:?profile seconds}"
tmpdir="$(mktemp -d /tmp/admin-pprof.XXXXXX)"

cleanup() {
  rm -f "${tmpdir}/admin.crt" "${tmpdir}/admin.key"
  rmdir "${tmpdir}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sudo awk '/client-certificate-data:/ { print $2; exit }' /etc/kubernetes/admin.conf | base64 -d > "${tmpdir}/admin.crt"
sudo awk '/client-key-data:/ { print $2; exit }' /etc/kubernetes/admin.conf | base64 -d > "${tmpdir}/admin.key"
chmod 600 "${tmpdir}/admin.crt" "${tmpdir}/admin.key"

curl -k -sS \
  --cert "${tmpdir}/admin.crt" \
  --key "${tmpdir}/admin.key" \
  "https://127.0.0.1:${pprof_port}/debug/pprof/profile?seconds=${profile_seconds}"
EOF_REMOTE
}

record_pprof_attempt_payload() {
  local src="$1"
  local dest="$2"

  if [[ -f "${src}" ]]; then
    mv "${src}" "${dest}"
  fi
}

start_controller_manager_pprof() {
  local deadline_epoch=""
  local attempt=0
  local tmp_profile=""
  local now_epoch=""
  local wait_rc=0
  local retry_reason=""
  local payload_excerpt=""
  local invalid_payload_file=""

  : > "${PPROF_LOG_FILE}"
  rm -f "${KCM_PPROF_FILE}" "${KCM_PPROF_TOP_FILE}" "${KCM_PPROF_FOCUSED_TOP_FILE}"

  deadline_epoch=$(( $(date +%s) + PPROF_START_TIMEOUT_SECONDS ))

  while true; do
    attempt=$((attempt + 1))
    tmp_profile="${KCM_PPROF_FILE}.attempt${attempt}.tmp"
    rm -f "${tmp_profile}"

    printf '[%s] Starting controller-manager pprof attempt %d\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "${attempt}" >> "${PPROF_LOG_FILE}"

    (
      capture_controller_manager_pprof > "${tmp_profile}"
    ) 2>> "${PPROF_LOG_FILE}" &
    PPROF_PID="$!"

    sleep "${PPROF_STARTUP_GRACE_SECONDS}"

    if kill -0 "${PPROF_PID}" >/dev/null 2>&1; then
      PPROF_STARTED="true"
      ACTIVE_PPROF_TMP_FILE="${tmp_profile}"
      ACTIVE_PPROF_START_ATTEMPT="${attempt}"
      printf '[%s] Controller-manager pprof attempt %d is running and reserved the profiler\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "${attempt}" >> "${PPROF_LOG_FILE}"
      return 0
    fi

    set +e
    wait "${PPROF_PID}"
    wait_rc=$?
    set -e

    retry_reason=""
    payload_excerpt=""
    if [[ -f "${tmp_profile}" ]]; then
      payload_excerpt="$(tr '\n' ' ' < "${tmp_profile}" | sed 's/[[:space:]]\+/ /g' | cut -c1-200)"
      if grep -qi 'cpu profiling already in use' "${tmp_profile}"; then
        retry_reason='cpu profiling already in use'
      fi
    fi

    invalid_payload_file="${KCM_PPROF_FILE}.startup-attempt${attempt}.payload.txt"
    record_pprof_attempt_payload "${tmp_profile}" "${invalid_payload_file}"

    if [[ -n "${retry_reason}" ]]; then
      printf '[%s] Controller-manager pprof attempt %d could not start: %s. Retrying in %ss\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "${attempt}" "${retry_reason}" "${PPROF_START_RETRY_SECONDS}" >> "${PPROF_LOG_FILE}"
    else
      printf '[%s] Controller-manager pprof attempt %d failed early (exit=%s). Payload excerpt: %s\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "${attempt}" "${wait_rc}" "${payload_excerpt:-<empty>}" >> "${PPROF_LOG_FILE}"
      return 1
    fi

    now_epoch="$(date +%s)"
    if (( now_epoch >= deadline_epoch )); then
      printf '[%s] Timed out waiting to acquire exclusive controller-manager CPU profiling\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "${PPROF_LOG_FILE}"
      return 1
    fi

    sleep "${PPROF_START_RETRY_SECONDS}"
  done
}

terminate_controller_manager_pprof() {
  if [[ "${PPROF_STARTED}" != "true" || -z "${PPROF_PID}" ]]; then
    return 0
  fi

  if kill -0 "${PPROF_PID}" >/dev/null 2>&1; then
    kill "${PPROF_PID}" >/dev/null 2>&1 || true
  fi
  wait "${PPROF_PID}" || true
}

wait_for_controller_manager_pprof() {
  if [[ "${PPROF_STARTED}" != "true" || -z "${PPROF_PID}" ]]; then
    return 0
  fi

  set +e
  wait "${PPROF_PID}"
  PPROF_EXIT_CODE=$?
  set -e

  return "${PPROF_EXIT_CODE}"
}

finalize_pprof_capture() {
  local parse_check_file="${KCM_PPROF_TOP_FILE}.tmp"

  if [[ -z "${ACTIVE_PPROF_TMP_FILE}" || ! -f "${ACTIVE_PPROF_TMP_FILE}" ]]; then
    printf '[%s] No controller-manager pprof payload file was captured\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "${PPROF_LOG_FILE}"
    return 1
  fi

  if ! "${GO_BINARY}" tool pprof -unit=s -top "${ACTIVE_PPROF_TMP_FILE}" > "${parse_check_file}" 2>> "${PPROF_LOG_FILE}"; then
    mv "${ACTIVE_PPROF_TMP_FILE}" "${KCM_PPROF_FILE}.invalid"
    rm -f "${parse_check_file}"
    printf '[%s] Captured controller-manager profile is not parseable. Saved invalid payload to %s.invalid\n' \
      "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "${KCM_PPROF_FILE}" >> "${PPROF_LOG_FILE}"
    return 1
  fi

  mv "${ACTIVE_PPROF_TMP_FILE}" "${KCM_PPROF_FILE}"
  mv "${parse_check_file}" "${KCM_PPROF_TOP_FILE}"
  return 0
}

write_process_summary() {
  if [[ ! -f "${PROCESS_SAMPLES_FILE}" ]]; then
    return 0
  fi

  awk -F, '
    BEGIN {
      OFS="\t"
      print "component", "samples", "avg_cpu_percent", "min_cpu_percent", "max_cpu_percent"
    }
    NR > 1 && $6 != "" {
      count[$3]++
      sum[$3] += $6
      if (!(($3) in min) || $6 < min[$3]) {
        min[$3] = $6
      }
      if (!(($3) in max) || $6 > max[$3]) {
        max[$3] = $6
      }
    }
    END {
      components[1] = "kube-scheduler"
      components[2] = "kube-controller-manager"
      for (i = 1; i <= 2; i++) {
        component = components[i]
        if (count[component] > 0) {
          printf "%s\t%d\t%.4f\t%.4f\t%.4f\n", component, count[component], sum[component] / count[component], min[component], max[component]
        } else {
          printf "%s\t0\tNA\tNA\tNA\n", component
        }
      }
    }
  ' "${PROCESS_SAMPLES_FILE}" > "${PROCESS_SUMMARY_FILE}"
}

get_process_avg_cpu_percent() {
  local component="$1"

  awk -F'\t' -v component="${component}" '
    $1 == component {
      print $3
      exit
    }
  ' "${PROCESS_SUMMARY_FILE}"
}

extract_pprof_total_percent() {
  local pprof_top_file="$1"

  awk '
    /Total samples =/ {
      line = $0
      sub(/^.*\(/, "", line)
      sub(/%\).*$/, "", line)
      gsub(/[[:space:]]/, "", line)
      if (line ~ /^[0-9.]+$/) {
        printf "%.4f\n", line
        exit
      }
    }
  ' "${pprof_top_file}"
}

analyze_controller_manager_pprof() {
  local whole_percent=""
  local focused_total_percent=""
  local focused_status=0

  if [[ ! -f "${KCM_PPROF_FILE}" ]]; then
    return 1
  fi

  if [[ ! -f "${KCM_PPROF_TOP_FILE}" ]]; then
    if ! "${GO_BINARY}" tool pprof -unit=s -top "${KCM_PPROF_FILE}" > "${KCM_PPROF_TOP_FILE}" 2>> "${PPROF_LOG_FILE}"; then
      return 1
    fi
  fi

  whole_percent="$(extract_pprof_total_percent "${KCM_PPROF_TOP_FILE}")"
  if [[ -n "${whole_percent}" ]]; then
    CONTROLLER_MANAGER_WHOLE_CPU_PERCENT="${whole_percent}"
    CONTROLLER_MANAGER_WHOLE_SOURCE="controller-manager-pprof-total"
    CONTROLLER_MANAGER_WHOLE_ARTIFACT="${KCM_PPROF_TOP_FILE}"
  fi

  set +e
  "${GO_BINARY}" tool pprof -unit=s -top -focus="${KCM_CONTROLLER_FOCUS_REGEX}" "${KCM_PPROF_FILE}" > "${KCM_PPROF_FOCUSED_TOP_FILE}" 2>> "${PPROF_LOG_FILE}"
  focused_status=$?
  set -e

  if [[ ${focused_status} -eq 0 ]]; then
    focused_total_percent="$(extract_pprof_total_percent "${KCM_PPROF_FOCUSED_TOP_FILE}")"
    if [[ -n "${focused_total_percent}" ]]; then
      TARGET_CONTROLLERS_COMBINED_CPU_PERCENT="${focused_total_percent}"
      TARGET_CONTROLLERS_COMBINED_SOURCE="controller-manager-pprof-focused-total"
    fi
  else
    printf '[%s] Focused controller-manager pprof report failed for regex %s\n' \
      "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "${KCM_CONTROLLER_FOCUS_REGEX}" >> "${PPROF_LOG_FILE}"
  fi

  return 0
}

write_summary() {
  cat > "${SUMMARY_FILE}" <<EOF_SUMMARY
metric	source	avg_cpu_percent	artifact
scheduler	process-sampling	${SCHEDULER_AVG_CPU_PERCENT}	${PROCESS_SUMMARY_FILE}
controller-manager-whole	${CONTROLLER_MANAGER_WHOLE_SOURCE}	${CONTROLLER_MANAGER_WHOLE_CPU_PERCENT}	${CONTROLLER_MANAGER_WHOLE_ARTIFACT}
controller-manager-job-ttlafterfinished-podgc-namespace-combined	${TARGET_CONTROLLERS_COMBINED_SOURCE}	${TARGET_CONTROLLERS_COMBINED_CPU_PERCENT}	${KCM_PPROF_FOCUSED_TOP_FILE}
controller-manager-process-cross-check	process-sampling	${CONTROLLER_MANAGER_PROCESS_AVG_CPU_PERCENT}	${PROCESS_SUMMARY_FILE}
EOF_SUMMARY
}

print_summary() {
  echo
  echo "[*] CPU usage results for the serverful run"
  echo "[*] Interpretation: 100% = one fully utilized vCPU"
  echo "  - scheduler: ${SCHEDULER_AVG_CPU_PERCENT}% (process average)"
  echo "  - controller manager as a whole: ${CONTROLLER_MANAGER_WHOLE_CPU_PERCENT}% (${CONTROLLER_MANAGER_WHOLE_SOURCE})"
  echo "  - job + ttlafterfinished + podgc + namespace controllers combined: ${TARGET_CONTROLLERS_COMBINED_CPU_PERCENT}% (${TARGET_CONTROLLERS_COMBINED_SOURCE})"
  echo "  - controller-manager process average cross-check: ${CONTROLLER_MANAGER_PROCESS_AVG_CPU_PERCENT}%"

  echo
  echo "[*] Saved artifacts"
  echo "  - Process samples: ${PROCESS_SAMPLES_FILE}"
  echo "  - Process summary: ${PROCESS_SUMMARY_FILE}"
  echo "  - Controller-manager pprof: ${KCM_PPROF_FILE}"
  echo "  - Controller-manager top: ${KCM_PPROF_TOP_FILE}"
  echo "  - Controller-manager focused top: ${KCM_PPROF_FOCUSED_TOP_FILE}"
  echo "  - Combined summary: ${SUMMARY_FILE}"
  echo "  - Test log: ${TEST_LOG_FILE}"
  echo "  - Process monitor log: ${MONITOR_LOG_FILE}"
  echo "  - Pprof log: ${PPROF_LOG_FILE}"
}

run_wrapped_test() {
  export RUN_ID
  export TEST_DURATION_SECONDS
  export SUBMISSION_INTERVAL_SECONDS
  export MAX_JOBS_PER_INTERVAL
  export TARGET_PENDING_PODS
  export TARGET_INFLIGHT_PODS

  set +e
  bash "${TEST_SCRIPT}" 2>&1 | tee "${TEST_LOG_FILE}"
  TEST_EXIT_CODE="${PIPESTATUS[0]}"
  set -e
}

finalize() {
  local exit_code="${1:-0}"
  local pprof_valid="false"

  if [[ "${FINALIZED}" == "true" ]]; then
    exit "${exit_code}"
  fi
  FINALIZED="true"

  trap - EXIT INT TERM

  stop_process_monitor
  write_process_summary || true

  SCHEDULER_AVG_CPU_PERCENT="$(get_process_avg_cpu_percent "kube-scheduler" || true)"
  CONTROLLER_MANAGER_PROCESS_AVG_CPU_PERCENT="$(get_process_avg_cpu_percent "kube-controller-manager" || true)"
  SCHEDULER_AVG_CPU_PERCENT="${SCHEDULER_AVG_CPU_PERCENT:-NA}"
  CONTROLLER_MANAGER_PROCESS_AVG_CPU_PERCENT="${CONTROLLER_MANAGER_PROCESS_AVG_CPU_PERCENT:-NA}"

  if [[ "${PPROF_STARTED}" == "true" ]]; then
    if [[ "${TEST_EXIT_CODE}" == "0" && "${exit_code}" == "0" ]]; then
      echo
      echo "[*] Waiting for controller-manager pprof capture to finish..."
      if ! wait_for_controller_manager_pprof; then
        echo "[!] Controller-manager pprof capture failed. See ${PPROF_LOG_FILE}" >&2
      fi
    else
      echo
      echo "[!] Stopping controller-manager pprof capture early because the wrapped test did not finish cleanly"
      terminate_controller_manager_pprof
    fi

    if finalize_pprof_capture; then
      pprof_valid="true"
    fi
  fi

  if [[ "${pprof_valid}" == "true" ]] && analyze_controller_manager_pprof; then
    :
  else
    CONTROLLER_MANAGER_WHOLE_CPU_PERCENT="${CONTROLLER_MANAGER_PROCESS_AVG_CPU_PERCENT}"
    CONTROLLER_MANAGER_WHOLE_SOURCE="process-sampling-fallback"
    CONTROLLER_MANAGER_WHOLE_ARTIFACT="${PROCESS_SUMMARY_FILE}"
  fi

  write_summary || true
  print_summary || true

  if [[ "${MONITOR_STARTED}" == "true" ]]; then
    printf 'ENDED_AT_UTC=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "${METADATA_FILE}"
    printf 'WRAPPED_TEST_EXIT_CODE=%s\n' "${TEST_EXIT_CODE}" >> "${METADATA_FILE}"
    printf 'PPROF_EXIT_CODE=%s\n' "${PPROF_EXIT_CODE}" >> "${METADATA_FILE}"
  fi

  close_ssh_connection
  exit "${exit_code}"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_cmd ssh
require_cmd awk
require_cmd date
require_cmd tee
require_cmd ps
require_cmd bash
require_cmd curl
require_cmd file
require_cmd base64
require_cmd "${GO_BINARY}"

require_positive_integer "TEST_DURATION_SECONDS" "${TEST_DURATION_SECONDS}"
require_positive_integer "PROFILE_SECONDS" "${PROFILE_SECONDS}"
require_positive_integer "SAMPLE_INTERVAL_SECONDS" "${SAMPLE_INTERVAL_SECONDS}"
require_positive_integer "SUBMISSION_INTERVAL_SECONDS" "${SUBMISSION_INTERVAL_SECONDS}"
require_positive_integer "MAX_JOBS_PER_INTERVAL" "${MAX_JOBS_PER_INTERVAL}"
require_positive_integer "KCM_PPROF_PORT" "${KCM_PPROF_PORT}"
require_positive_integer "PPROF_STARTUP_GRACE_SECONDS" "${PPROF_STARTUP_GRACE_SECONDS}"
require_positive_integer "PPROF_START_RETRY_SECONDS" "${PPROF_START_RETRY_SECONDS}"
require_positive_integer "PPROF_START_TIMEOUT_SECONDS" "${PPROF_START_TIMEOUT_SECONDS}"
require_boolean "REQUIRE_CONTROLLER_MANAGER_PPROF" "${REQUIRE_CONTROLLER_MANAGER_PPROF}"

[[ -f "${TEST_SCRIPT}" ]] || { echo "Missing wrapped test script: ${TEST_SCRIPT}" >&2; exit 1; }
[[ -n "${SSH_HOST}" ]] || { echo "Missing SSH host. Set SSH_HOST or ensure ${CLUSTER_ENV_FILE} exports CONTROL_PUB." >&2; exit 1; }
[[ -n "${SSH_IDENTITY_FILE}" ]] || { echo "Missing SSH identity file. Set SSH_IDENTITY_FILE or ensure ${CLUSTER_ENV_FILE} exports IDENTITY_FILE." >&2; exit 1; }
[[ -f "${SSH_IDENTITY_FILE}" ]] || { echo "SSH identity file not found: ${SSH_IDENTITY_FILE}" >&2; exit 1; }

SSH_OPTS=(
  -o BatchMode=yes
  -o StrictHostKeyChecking=no
  -o IdentitiesOnly=yes
  -o PreferredAuthentications=publickey
  -i "${SSH_IDENTITY_FILE}"
  -o ControlMaster=auto
  -o ControlPath="${SOCK_DIR}/%r@%h:%p"
  -o ControlPersist=600
)

trap 'finalize $?' EXIT
trap 'TEST_EXIT_CODE=130; finalize 130' INT TERM

echo "[*] Starting serverful control-plane monitor for ${SSH_HOST}"
echo "[*] Process sampling interval: ${SAMPLE_INTERVAL_SECONDS}s"
echo "[*] Controller-manager pprof duration: ${PROFILE_SECONDS}s"
echo "[*] Wrapped test script: ${TEST_SCRIPT}"
echo "[*] Artifacts directory: ${MONITOR_OUT_DIR}"
echo "[*] Test duration: ${TEST_DURATION_SECONDS}s"
echo "[*] Scheduler load target: pending=${TARGET_PENDING_PODS} inflight=${TARGET_INFLIGHT_PODS}"

start_process_monitor
if ! start_controller_manager_pprof; then
  echo "[!] Could not acquire a valid controller-manager CPU profile before the run. See ${PPROF_LOG_FILE}" >&2
  if [[ "${REQUIRE_CONTROLLER_MANAGER_PPROF}" == "true" ]]; then
    TEST_EXIT_CODE=1
    finalize 1
  fi
fi
run_wrapped_test

finalize "${TEST_EXIT_CODE}"
