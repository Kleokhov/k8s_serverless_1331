#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/shutdown/shutdown_serverless.sh MODE [options]

Modes:
  apiserver  Delete Lambda apiserver stack, its DynamoDB storage tables (created
             outside CloudFormation by precreate_dynamo_tables.sh), the SSM
             kubeconfig parameter, and the local kubeconfig file.
  scheduler  Delete the Lambda scheduler/dispatcher/controllers CloudFormation
             stack (Lambda functions, SQS queues, DynamoDB queue/cache tables,
             event rules).
  workers    Terminate the serverless worker EC2 instances (tagged
             Project=${TAG_PREFIX} Role=serverless-worker). Shared network and
             IAM infrastructure is left in place for reuse.
  all        apiserver + scheduler + workers, torn down in a safe order.

Options:
      --region REGION               AWS region (default: us-east-1)
      --tag-prefix PREFIX           Tag prefix used for workers
                                    (default: ctrlless-serverless)
      --apiserver-stack NAME        CloudFormation stack for the apiserver
                                    (default: ctrlless-serverless-apiserver)
      --scheduler-stack NAME        CloudFormation stack for the scheduler
                                    (default: ctrlless-serverless-lambda)
      --apiserver-table-prefix P    DynamoDB table base used by the apiserver
                                    (default: ctrlless-serverless-apiserver)
      --kubeconfig-parameter NAME   SSM parameter name holding the apiserver
                                    kubeconfig
                                    (default: /ctrlless-serverless/admin-kubeconfig)
      --kubeconfig-file PATH        Local kubeconfig file to remove
                                    (default: <repo>/_serverless_out/lambda-apiserver.kubeconfig)
      --workers-env PATH            Path to workers.env
                                    (default: <repo>/_serverless_out/workers.env)
      --apiserver-log-prefix P      CloudWatch /aws/lambda prefix to sweep
                                    for the apiserver functions
                                    (default: <apiserver-stack>-)
      --scheduler-log-prefix P      CloudWatch /aws/lambda prefix to sweep
                                    for the scheduler/controller functions
                                    (default: <scheduler-stack>-)
      --apiserver-artifact-bucket B S3 bucket containing apiserver SAM artifacts
      --scheduler-artifact-bucket B S3 bucket containing scheduler/controller
                                    SAM artifacts
      --keep-local-files            Do not remove the local kubeconfig or
                                    workers.env files.
      --keep-dynamo                 Do not delete the apiserver DynamoDB tables.
      --keep-ssm                    Do not delete the kubeconfig SSM parameter.
      --keep-log-groups             Do not delete CloudWatch log groups.
      --keep-artifact-buckets       Do not empty/delete component SAM artifact
                                    buckets.
      --keep-sam-bucket             Backward-compatible alias for
                                    --keep-artifact-buckets.
  -y, --yes                         Skip confirmation prompts.
  -h, --help                        Show this help.

Environment overrides:
  AWS_REGION, TAG_PREFIX, SERVERLESS_RESOURCE_PREFIX,
  APISERVER_STACK_NAME, SCHEDULER_STACK_NAME,
  APISERVER_DYNAMO_TABLE, KUBECONFIG_PARAMETER_NAME,
  APISERVER_ARTIFACT_BUCKET, SCHEDULER_ARTIFACT_BUCKET

Notes:
  - Modes are idempotent: missing stacks/tables/instances/files/log groups are
    skipped.
  - "all" order: workers -> scheduler -> apiserver. Workers only talk to the
    apiserver through SSM, so removing them first avoids noisy failures.
  - Shared VPC/subnet/security-group/IAM-role resources are intentionally NOT
    deleted; they are reused across deploys and managed by
    scripts/ec2_k8s/setup_ec2.sh.
  - CloudWatch log groups for Lambda (/aws/lambda/<FunctionName>) are created
    by the Lambda service, not CloudFormation, so they survive stack deletion
    and are swept here.
  - Component SAM artifact buckets are deterministic and per component:
    <prefix>-lambda-apiserver-<account>-<region> and
    <prefix>-lambda-controllers-<account>-<region>. They are emptied and
    deleted with their corresponding component unless --keep-artifact-buckets
    is set.
EOF
}

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 1; }
}

MODE="${1:-}"
if [[ -z "${MODE}" ]]; then
  usage
  exit 1
fi
shift || true

case "${MODE}" in
  apiserver|scheduler|workers|all) ;;
  -h|--help) usage; exit 0 ;;
  *)
    echo "Unknown mode: ${MODE}" >&2
    usage
    exit 1
    ;;
esac

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_LOCAL_DIR="${REPO_LOCAL_DIR:-$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel 2>/dev/null || (cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd))}"
OUT_DIR="${OUT_DIR:-${REPO_LOCAL_DIR}/_serverless_out}"

AWS_REGION="${AWS_REGION:-us-east-1}"
TAG_PREFIX="${TAG_PREFIX:-ctrlless-serverless}"
SERVERLESS_RESOURCE_PREFIX="${SERVERLESS_RESOURCE_PREFIX:-${TAG_PREFIX}}"
APISERVER_STACK_NAME="${APISERVER_STACK_NAME:-${SERVERLESS_RESOURCE_PREFIX}-apiserver}"
SCHEDULER_STACK_NAME="${SCHEDULER_STACK_NAME:-${SERVERLESS_RESOURCE_PREFIX}-lambda}"
APISERVER_DYNAMO_TABLE="${APISERVER_DYNAMO_TABLE:-${SERVERLESS_RESOURCE_PREFIX}-apiserver}"
KUBECONFIG_PARAMETER_NAME="${KUBECONFIG_PARAMETER_NAME:-/${SERVERLESS_RESOURCE_PREFIX}/admin-kubeconfig}"
KUBECONFIG_FILE="${KUBECONFIG_FILE:-${OUT_DIR}/lambda-apiserver.kubeconfig}"
WORKERS_ENV="${WORKERS_ENV:-${OUT_DIR}/workers.env}"
APISERVER_LOG_PREFIX="${APISERVER_LOG_PREFIX:-${APISERVER_STACK_NAME}-}"
SCHEDULER_LOG_PREFIX="${SCHEDULER_LOG_PREFIX:-${SCHEDULER_STACK_NAME}-}"
APISERVER_ARTIFACT_BUCKET="${APISERVER_ARTIFACT_BUCKET:-}"
SCHEDULER_ARTIFACT_BUCKET="${SCHEDULER_ARTIFACT_BUCKET:-}"

YES="false"
KEEP_LOCAL_FILES="false"
KEEP_DYNAMO="false"
KEEP_SSM="false"
KEEP_LOG_GROUPS="false"
KEEP_ARTIFACT_BUCKETS="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --region) AWS_REGION="$2"; shift 2 ;;
    --tag-prefix) TAG_PREFIX="$2"; shift 2 ;;
    --apiserver-stack) APISERVER_STACK_NAME="$2"; shift 2 ;;
    --scheduler-stack) SCHEDULER_STACK_NAME="$2"; shift 2 ;;
    --apiserver-table-prefix) APISERVER_DYNAMO_TABLE="$2"; shift 2 ;;
    --kubeconfig-parameter) KUBECONFIG_PARAMETER_NAME="$2"; shift 2 ;;
    --kubeconfig-file) KUBECONFIG_FILE="$2"; shift 2 ;;
    --workers-env) WORKERS_ENV="$2"; shift 2 ;;
    --apiserver-log-prefix) APISERVER_LOG_PREFIX="$2"; shift 2 ;;
    --scheduler-log-prefix) SCHEDULER_LOG_PREFIX="$2"; shift 2 ;;
    --apiserver-artifact-bucket) APISERVER_ARTIFACT_BUCKET="$2"; shift 2 ;;
    --scheduler-artifact-bucket) SCHEDULER_ARTIFACT_BUCKET="$2"; shift 2 ;;
    --sam-managed-stack)
      echo "[*] Ignoring deprecated --sam-managed-stack; component artifact buckets are used now."
      shift 2
      ;;
    --keep-local-files) KEEP_LOCAL_FILES="true"; shift ;;
    --keep-dynamo) KEEP_DYNAMO="true"; shift ;;
    --keep-ssm) KEEP_SSM="true"; shift ;;
    --keep-log-groups) KEEP_LOG_GROUPS="true"; shift ;;
    --keep-artifact-buckets|--keep-sam-bucket) KEEP_ARTIFACT_BUCKETS="true"; shift ;;
    -y|--yes) YES="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

need aws
need jq

default_artifact_bucket_name() {
  local component="$1"
  local raw name hash suffix prefix_len prefix

  raw="${SERVERLESS_RESOURCE_PREFIX}-${component}-${AWS_ACCOUNT_ID}-${AWS_REGION}"
  name="$(
    printf '%s' "${raw}" \
      | tr '[:upper:]' '[:lower:]' \
      | tr -c 'a-z0-9.-' '-' \
      | sed -E 's/^[.-]+//; s/[.-]+$//; s/[.-]{2,}/-/g'
  )"

  if [[ ${#name} -gt 63 ]]; then
    hash="$(printf '%s' "${name}" | cksum | awk '{print $1}')"
    suffix="-${AWS_ACCOUNT_ID}-${AWS_REGION}-${hash}"
    prefix_len=$((63 - ${#suffix}))
    prefix="${name:0:${prefix_len}}"
    prefix="$(printf '%s' "${prefix}" | sed -E 's/[.-]+$//')"
    name="${prefix}${suffix}"
  fi

  printf '%s\n' "${name}"
}

AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-$(aws sts get-caller-identity --query 'Account' --output text)}"
APISERVER_ARTIFACT_BUCKET="${APISERVER_ARTIFACT_BUCKET:-$(default_artifact_bucket_name lambda-apiserver)}"
SCHEDULER_ARTIFACT_BUCKET="${SCHEDULER_ARTIFACT_BUCKET:-$(default_artifact_bucket_name lambda-controllers)}"

confirm() {
  local prompt="$1"
  if [[ "${YES}" == "true" ]]; then
    return 0
  fi
  read -r -p "${prompt} [y/N] " answer
  case "${answer}" in
    y|Y|yes|YES) ;;
    *) echo "Aborted."; exit 1 ;;
  esac
}

######################## CloudFormation helpers ########################

stack_exists() {
  aws cloudformation describe-stacks \
    --region "${AWS_REGION}" \
    --stack-name "$1" >/dev/null 2>&1
}

delete_stack_if_present() {
  local stack_name="$1"
  local status

  if ! stack_exists "${stack_name}"; then
    echo "[*] CloudFormation stack not found: ${stack_name}"
    return 0
  fi

  status="$(aws cloudformation describe-stacks \
    --region "${AWS_REGION}" \
    --stack-name "${stack_name}" \
    --query 'Stacks[0].StackStatus' \
    --output text)"

  if [[ "${status}" == "DELETE_IN_PROGRESS" ]]; then
    echo "[*] Stack delete already in progress: ${stack_name}"
  else
    echo "[*] Deleting CloudFormation stack: ${stack_name}"
    aws cloudformation delete-stack --region "${AWS_REGION}" --stack-name "${stack_name}"
  fi
  aws cloudformation wait stack-delete-complete \
    --region "${AWS_REGION}" \
    --stack-name "${stack_name}"
  echo "[+] Stack deleted: ${stack_name}"
}

######################## DynamoDB helpers ########################

list_apiserver_tables() {
  local prefix="$1"
  aws dynamodb list-tables \
    --region "${AWS_REGION}" \
    --query 'TableNames[]' \
    --output text 2>/dev/null \
    | tr '\t' '\n' \
    | awk -v p="${prefix}" '$0==p || index($0, p"-")==1'
}

delete_table_if_present() {
  local table="$1"
  if ! aws dynamodb describe-table \
        --region "${AWS_REGION}" \
        --table-name "${table}" >/dev/null 2>&1; then
    echo "[*] DynamoDB table not found: ${table}"
    return 0
  fi
  echo "[*] Deleting DynamoDB table: ${table}"
  aws dynamodb delete-table \
    --region "${AWS_REGION}" \
    --table-name "${table}" >/dev/null
}

delete_apiserver_dynamo_tables() {
  local prefix="$1"
  local tables
  tables="$(list_apiserver_tables "${prefix}" || true)"
  if [[ -z "${tables}" ]]; then
    echo "[*] No apiserver DynamoDB tables matched prefix: ${prefix}"
    return 0
  fi

  echo "[*] Apiserver DynamoDB tables to delete:"
  while IFS= read -r t; do
    [[ -n "${t}" ]] && echo "      ${t}"
  done <<<"${tables}"

  while IFS= read -r t; do
    [[ -z "${t}" ]] && continue
    delete_table_if_present "${t}"
  done <<<"${tables}"

  echo "[*] Waiting for apiserver DynamoDB tables to finish deleting"
  while IFS= read -r t; do
    [[ -z "${t}" ]] && continue
    aws dynamodb wait table-not-exists \
      --region "${AWS_REGION}" \
      --table-name "${t}" || true
  done <<<"${tables}"
  echo "[+] Apiserver DynamoDB tables removed."
}

######################## SSM helpers ########################

delete_ssm_parameter_if_present() {
  local name="$1"
  if ! aws ssm get-parameter \
        --region "${AWS_REGION}" \
        --name "${name}" >/dev/null 2>&1; then
    echo "[*] SSM parameter not found: ${name}"
    return 0
  fi
  echo "[*] Deleting SSM parameter: ${name}"
  aws ssm delete-parameter --region "${AWS_REGION}" --name "${name}" >/dev/null
}

######################## CloudWatch Logs helpers ########################

delete_log_groups_by_prefix() {
  local prefix="$1"
  local full_prefix="/aws/lambda/${prefix}"
  local names next_token="" page
  declare -a groups=()

  while :; do
    if [[ -n "${next_token}" ]]; then
      page="$(aws logs describe-log-groups \
        --region "${AWS_REGION}" \
        --log-group-name-prefix "${full_prefix}" \
        --starting-token "${next_token}" \
        --output json 2>/dev/null || echo '{}')"
    else
      page="$(aws logs describe-log-groups \
        --region "${AWS_REGION}" \
        --log-group-name-prefix "${full_prefix}" \
        --output json 2>/dev/null || echo '{}')"
    fi

    names="$(printf '%s' "${page}" | jq -r '.logGroups[]?.logGroupName // empty')"
    while IFS= read -r name; do
      [[ -n "${name}" ]] && groups+=("${name}")
    done <<<"${names}"

    next_token="$(printf '%s' "${page}" | jq -r '.NextToken // empty')"
    [[ -z "${next_token}" ]] && break
  done

  if [[ ${#groups[@]} -eq 0 ]]; then
    echo "[*] No log groups under ${full_prefix}"
    return 0
  fi

  echo "[*] Deleting ${#groups[@]} log group(s) under ${full_prefix}:"
  for g in "${groups[@]}"; do
    echo "      ${g}"
  done
  for g in "${groups[@]}"; do
    aws logs delete-log-group \
      --region "${AWS_REGION}" \
      --log-group-name "${g}" >/dev/null 2>&1 || true
  done
  echo "[+] Log groups removed for prefix ${full_prefix}."
}

######################## SAM artifact bucket helpers ########################

empty_s3_bucket() {
  local bucket="$1"
  local versions_json delete_payload object_count

  echo "[*] Emptying S3 bucket: s3://${bucket}"
  aws s3 rm "s3://${bucket}" --recursive --region "${AWS_REGION}" >/dev/null 2>&1 || true

  while :; do
    versions_json="$(aws s3api list-object-versions --region "${AWS_REGION}" --bucket "${bucket}" --output json 2>/dev/null || echo '{}')"
    object_count="$(printf '%s' "${versions_json}" | jq '((.Versions // []) + (.DeleteMarkers // [])) | length')"
    if [[ "${object_count}" == "0" ]]; then
      break
    fi

    delete_payload="$(printf '%s' "${versions_json}" | jq -c '{
      Objects: (((.Versions // []) + (.DeleteMarkers // [])) | map({Key: .Key, VersionId: .VersionId})),
      Quiet: true
    }')"

    aws s3api delete-objects \
      --region "${AWS_REGION}" \
      --bucket "${bucket}" \
      --delete "${delete_payload}" >/dev/null
  done
}

delete_artifact_bucket_if_present() {
  local bucket="$1"
  local head_output

  if [[ -z "${bucket}" ]]; then
    return 0
  fi

  if head_output="$(aws s3api head-bucket --region "${AWS_REGION}" --bucket "${bucket}" 2>&1)"; then
    empty_s3_bucket "${bucket}"
    aws s3api delete-bucket --region "${AWS_REGION}" --bucket "${bucket}" >/dev/null
    echo "[+] Deleted SAM artifact bucket: s3://${bucket}"
  elif printf '%s' "${head_output}" | grep -Eq '\(404\)|Not Found|NoSuchBucket'; then
    echo "[*] SAM artifact bucket not found: s3://${bucket}"
  else
    echo "Cannot access S3 bucket ${bucket}; leaving it in place."
    echo "${head_output}"
    return 1
  fi
}

######################## EC2 worker helpers ########################

list_worker_instance_ids() {
  aws ec2 describe-instances \
    --region "${AWS_REGION}" \
    --filters "Name=tag:Project,Values=${TAG_PREFIX}" \
              "Name=tag:Role,Values=serverless-worker" \
              "Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down" \
    --query 'Reservations[].Instances[].InstanceId' \
    --output text 2>/dev/null || true
}

list_worker_ids_from_env() {
  local env_path="$1"
  [[ -f "${env_path}" ]] || return 0
  # shellcheck disable=SC1090
  (
    set +u
    source "${env_path}"
    for var in $(compgen -A variable | grep -E '^WORKER[0-9]+_ID$' | sort); do
      printf '%s\n' "${!var}"
    done
    if [[ -n "${WORKER_IDS:-}" ]]; then
      for id in ${WORKER_IDS}; do
        printf '%s\n' "${id}"
      done
    fi
  )
}

terminate_serverless_workers() {
  local ids_txt
  local env_ids
  declare -a ids=()
  declare -A seen=()

  ids_txt="$(list_worker_instance_ids)"
  if [[ -n "${ids_txt}" && "${ids_txt}" != "None" ]]; then
    for id in ${ids_txt}; do
      if [[ -z "${seen[$id]:-}" ]]; then
        ids+=("${id}")
        seen[$id]=1
      fi
    done
  fi

  env_ids="$(list_worker_ids_from_env "${WORKERS_ENV}" || true)"
  if [[ -n "${env_ids}" ]]; then
    while IFS= read -r id; do
      [[ -z "${id}" ]] && continue
      if [[ -z "${seen[$id]:-}" ]]; then
        ids+=("${id}")
        seen[$id]=1
      fi
    done <<<"${env_ids}"
  fi

  if [[ ${#ids[@]} -eq 0 ]]; then
    echo "[*] No serverless worker instances found for Project=${TAG_PREFIX}."
    return 0
  fi

  local ids_csv
  ids_csv="$(IFS=,; printf '%s' "${ids[*]}")"
  local terminatable_txt
  terminatable_txt="$(aws ec2 describe-instances \
    --region "${AWS_REGION}" \
    --filters "Name=instance-id,Values=${ids_csv}" \
              "Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down" \
    --query 'Reservations[].Instances[].InstanceId' \
    --output text 2>/dev/null || true)"

  declare -a terminatable=()
  for id in ${terminatable_txt}; do
    terminatable+=("${id}")
  done

  if [[ ${#terminatable[@]} -eq 0 ]]; then
    echo "[*] Serverless workers already terminated."
    return 0
  fi

  echo "[*] Terminating serverless worker instances: ${terminatable[*]}"
  aws ec2 terminate-instances \
    --region "${AWS_REGION}" \
    --instance-ids "${terminatable[@]}" >/dev/null
  aws ec2 wait instance-terminated \
    --region "${AWS_REGION}" \
    --instance-ids "${terminatable[@]}"
  echo "[+] Serverless worker instances terminated."
}

remove_local_file_if_present() {
  local path="$1"
  [[ -e "${path}" ]] || return 0
  echo "[*] Removing local file: ${path}"
  rm -f "${path}"
}

######################## Mode entrypoints ########################

teardown_apiserver() {
  echo "== tearing down lambda apiserver =="
  echo "  region:              ${AWS_REGION}"
  echo "  stack:               ${APISERVER_STACK_NAME}"
  echo "  dynamo table prefix: ${APISERVER_DYNAMO_TABLE}"
  echo "  kubeconfig ssm:      ${KUBECONFIG_PARAMETER_NAME}"
  echo "  log group prefix:    /aws/lambda/${APISERVER_LOG_PREFIX}"
  echo "  artifact bucket:     ${APISERVER_ARTIFACT_BUCKET}"
  echo

  delete_stack_if_present "${APISERVER_STACK_NAME}"

  if [[ "${KEEP_DYNAMO}" == "true" ]]; then
    echo "[*] Skipping apiserver DynamoDB cleanup (--keep-dynamo)"
  else
    delete_apiserver_dynamo_tables "${APISERVER_DYNAMO_TABLE}"
  fi

  if [[ "${KEEP_SSM}" == "true" ]]; then
    echo "[*] Skipping SSM kubeconfig cleanup (--keep-ssm)"
  else
    delete_ssm_parameter_if_present "${KUBECONFIG_PARAMETER_NAME}"
  fi

  if [[ "${KEEP_LOG_GROUPS}" == "true" ]]; then
    echo "[*] Skipping CloudWatch log-group cleanup (--keep-log-groups)"
  else
    delete_log_groups_by_prefix "${APISERVER_LOG_PREFIX}"
  fi

  if [[ "${KEEP_ARTIFACT_BUCKETS}" == "true" ]]; then
    echo "[*] Skipping SAM artifact bucket cleanup (--keep-artifact-buckets)"
  else
    delete_artifact_bucket_if_present "${APISERVER_ARTIFACT_BUCKET}"
  fi

  if [[ "${KEEP_LOCAL_FILES}" != "true" ]]; then
    remove_local_file_if_present "${KUBECONFIG_FILE}"
  fi
}

teardown_scheduler() {
  echo "== tearing down lambda scheduler/dispatcher/controllers =="
  echo "  region:           ${AWS_REGION}"
  echo "  stack:            ${SCHEDULER_STACK_NAME}"
  echo "  log group prefix: /aws/lambda/${SCHEDULER_LOG_PREFIX}"
  echo "  artifact bucket:  ${SCHEDULER_ARTIFACT_BUCKET}"
  echo
  delete_stack_if_present "${SCHEDULER_STACK_NAME}"

  if [[ "${KEEP_LOG_GROUPS}" == "true" ]]; then
    echo "[*] Skipping CloudWatch log-group cleanup (--keep-log-groups)"
  else
    delete_log_groups_by_prefix "${SCHEDULER_LOG_PREFIX}"
  fi

  if [[ "${KEEP_ARTIFACT_BUCKETS}" == "true" ]]; then
    echo "[*] Skipping SAM artifact bucket cleanup (--keep-artifact-buckets)"
  else
    delete_artifact_bucket_if_present "${SCHEDULER_ARTIFACT_BUCKET}"
  fi
}

teardown_workers() {
  echo "== tearing down serverless worker nodes =="
  echo "  region:      ${AWS_REGION}"
  echo "  tag prefix:  ${TAG_PREFIX}"
  echo "  workers.env: ${WORKERS_ENV}"
  echo
  terminate_serverless_workers
  if [[ "${KEEP_LOCAL_FILES}" != "true" ]]; then
    remove_local_file_if_present "${WORKERS_ENV}"
  fi
}

case "${MODE}" in
  apiserver)
    confirm "Delete apiserver stack ${APISERVER_STACK_NAME}, its DynamoDB tables (prefix ${APISERVER_DYNAMO_TABLE}), SSM parameter ${KUBECONFIG_PARAMETER_NAME}, /aws/lambda/${APISERVER_LOG_PREFIX}* log groups, and artifact bucket ${APISERVER_ARTIFACT_BUCKET}?"
    teardown_apiserver
    ;;
  scheduler)
    confirm "Delete scheduler stack ${SCHEDULER_STACK_NAME}, /aws/lambda/${SCHEDULER_LOG_PREFIX}* log groups, and artifact bucket ${SCHEDULER_ARTIFACT_BUCKET}?"
    teardown_scheduler
    ;;
  workers)
    confirm "Terminate serverless worker instances (Project=${TAG_PREFIX}, Role=serverless-worker)?"
    teardown_workers
    ;;
  all)
    confirm "Tear down workers, scheduler stack ${SCHEDULER_STACK_NAME}, apiserver stack ${APISERVER_STACK_NAME} (with DynamoDB tables and SSM kubeconfig), their Lambda log groups, and component artifact buckets ${SCHEDULER_ARTIFACT_BUCKET} and ${APISERVER_ARTIFACT_BUCKET}?"
    teardown_workers
    teardown_scheduler
    teardown_apiserver
    ;;
esac

echo
echo "Done."
