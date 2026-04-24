#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/shutdown/shutdown_ec2_partial_cluster.sh MODE [options]

Modes:
  cluster   Terminate the EC2 cluster instances listed in _ec2_out/cluster.env
  lambda    Delete the Lambda/SAM application and optionally clean up S3 buckets
  both      Delete the Lambda application and terminate the EC2 cluster instances

Options:
      --cluster-env PATH  Path to cluster.env (default: repo/_ec2_out/cluster.env)
      --stack-name NAME   CloudFormation stack name for the Lambda application
      --s3-bucket [NAME]  S3 bucket to empty and delete; may be repeated.
                         If NAME is omitted, delete the SAM-managed artifact
                         bucket from aws-sam-cli-managed-default.
  -y, --yes               Skip confirmation prompts
  -h, --help              Show this help

Environment:
  LAMBDA_STACK_NAME / APP_STACK_NAME / SAM_STACK_NAME
      Default stack name if --stack-name is omitted.
  LAMBDA_S3_BUCKETS / APP_S3_BUCKETS
      Space-separated list of S3 buckets to clean up when MODE includes lambda.
  SAM_CLI_MANAGED_STACK_NAME
      Default SAM managed stack used to discover the artifact bucket when
      --s3-bucket is passed without a name.

Notes:
  - "cluster" terminates the EC2 instances so a fresh
    ./scripts/ec2_k8s/setup_ec2.sh -b create can launch a new deployment.
  - "both" deletes the Lambda stack and terminates the EC2 instances, but it still
    leaves shared infrastructure such as the VPC, subnet, security group, IAM
    role, and instance profile in place for reuse.
  - "lambda" deletes the Lambda/SAM stack. S3 cleanup only happens for buckets
    you pass explicitly, via LAMBDA_S3_BUCKETS or APP_S3_BUCKETS, or by passing
    --s3-bucket without a name to target the SAM-managed artifact bucket.
EOF
}

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1"; exit 1; }
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_LOCAL_DIR="${REPO_LOCAL_DIR:-$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel 2>/dev/null || (cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd))}"
OUT_DIR="${OUT_DIR:-${REPO_LOCAL_DIR}/_ec2_out}"
DEFAULT_CLUSTER_ENV="${OUT_DIR}/cluster.env"

MODE="${1:-}"
if [[ -z "${MODE}" ]]; then
  usage
  exit 1
fi
shift || true

case "${MODE}" in
  cluster|lambda|both) ;;
  app)
    echo "[*] Mode 'app' is deprecated; use 'lambda'."
    MODE="lambda"
    ;;
  -h|--help) usage; exit 0 ;;
  *)
    echo "Unknown mode: ${MODE}"
    usage
    exit 1
    ;;
esac

CLUSTER_ENV="${DEFAULT_CLUSTER_ENV}"
STACK_NAME="${LAMBDA_STACK_NAME:-${APP_STACK_NAME:-${SAM_STACK_NAME:-}}}"
SAM_MANAGED_STACK_NAME="${SAM_CLI_MANAGED_STACK_NAME:-aws-sam-cli-managed-default}"
DELETE_SAM_MANAGED_BUCKET="false"
YES="false"
declare -a S3_BUCKETS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cluster-env) CLUSTER_ENV="$2"; shift 2 ;;
    --stack-name)  STACK_NAME="$2"; shift 2 ;;
    --s3-bucket)
      if [[ $# -gt 1 && "${2}" != --* && "${2}" != -* ]]; then
        S3_BUCKETS+=("$2")
        shift 2
      else
        DELETE_SAM_MANAGED_BUCKET="true"
        shift
      fi
      ;;
    --terminate-cluster) shift ;; # Backward-compatible no-op: cluster now always terminates.
    -y|--yes)      YES="true"; shift ;;
    -h|--help)     usage; exit 0 ;;
    *)
      echo "Unknown arg: $1"
      usage
      exit 1
      ;;
  esac
done

need aws
need jq

load_cluster_env() {
  if [[ -f "${CLUSTER_ENV}" ]]; then
    # shellcheck source=/dev/null
    source "${CLUSTER_ENV}"
  elif [[ "${MODE}" == "cluster" || "${MODE}" == "both" ]]; then
    echo "Missing cluster env: ${CLUSTER_ENV}"
    exit 1
  fi

  AWS_REGION="${AWS_REGION:-us-east-1}"
  TAG_PREFIX="${TAG_PREFIX:-ctrlless}"
}

resolve_stack_name() {
  if [[ -n "${STACK_NAME}" ]]; then
    return 0
  fi
  STACK_NAME="${TAG_PREFIX:-ctrlless}-mt"
}

stack_exists() {
  aws cloudformation describe-stacks \
    --region "${AWS_REGION}" \
    --stack-name "${STACK_NAME}" >/dev/null 2>&1
}

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

append_s3_bucket() {
  local bucket="$1"
  local existing

  [[ -z "${bucket}" || "${bucket}" == "None" ]] && return 0

  for existing in "${S3_BUCKETS[@]}"; do
    [[ "${existing}" == "${bucket}" ]] && return 0
  done

  S3_BUCKETS+=("${bucket}")
}

append_unique_items() {
  local target_name="$1"
  shift || true

  local -n target_ref="${target_name}"
  local item existing found

  for item in "$@"; do
    for item in ${item}; do
      [[ -z "${item}" || "${item}" == "None" ]] && continue

      found=0
      for existing in "${target_ref[@]}"; do
        if [[ "${existing}" == "${item}" ]]; then
          found=1
          break
        fi
      done

      if [[ "${found}" == "0" ]]; then
        target_ref+=("${item}")
      fi
    done
  done
}

collect_cluster_instance_ids() {
  local target_name="$1"
  local -n ids_ref="${target_name}"
  local worker_var
  local discovered=""

  ids_ref=()

  append_unique_items "${target_name}" "${ID_STORAGE:-}" "${ID_CONTROL:-}"

  while IFS= read -r worker_var; do
    [[ "${worker_var}" =~ ^WORKER[0-9]+_ID$ ]] || continue
    append_unique_items "${target_name}" "${!worker_var:-}"
  done < <(compgen -A variable | sort)

  append_unique_items "${target_name}" "${WORKER_IDS:-}"

  if [[ -n "${K8S_CLUSTER_NAME:-}" ]]; then
    discovered="$(aws ec2 describe-instances \
      --region "${AWS_REGION}" \
      --filters "Name=tag:Name,Values=${K8S_CLUSTER_NAME}-*" \
                "Name=instance-state-name,Values=pending,running,stopping,stopped" \
      --query 'Reservations[].Instances[].InstanceId' \
      --output text 2>/dev/null || true)"
    append_unique_items "${target_name}" "${discovered}"
  fi

  if [[ ${#ids_ref[@]} -gt 0 ]]; then
    return 0
  fi

  if [[ -n "${TAG_PREFIX:-}" ]]; then
    discovered="$(aws ec2 describe-instances \
      --region "${AWS_REGION}" \
      --filters "Name=tag:Project,Values=${TAG_PREFIX}" \
                "Name=instance-state-name,Values=pending,running,stopping,stopped" \
      --query 'Reservations[].Instances[].InstanceId' \
      --output text 2>/dev/null || true)"
    append_unique_items "${target_name}" "${discovered}"
  fi
}

terminate_cluster_instances() {
  local ids=()
  local terminatable=()
  local ids_csv
  local terminatable_txt

  collect_cluster_instance_ids ids
  if [[ ${#ids[@]} -eq 0 ]]; then
    echo "[*] No cluster instance IDs found; nothing to terminate."
    return 0
  fi

  ids_csv="$(IFS=,; printf '%s' "${ids[*]}")"
  terminatable_txt="$(aws ec2 describe-instances \
    --region "${AWS_REGION}" \
    --filters "Name=instance-id,Values=${ids_csv}" \
              "Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down" \
    --query 'Reservations[].Instances[].InstanceId' \
    --output text 2>/dev/null || true)"

  append_unique_items terminatable "${terminatable_txt}"

  if [[ ${#terminatable[@]} -eq 0 ]]; then
    echo "[*] Cluster instances are already terminated."
    return 0
  fi

  echo "[*] Terminating cluster instances: ${terminatable[*]}"
  aws ec2 terminate-instances --region "${AWS_REGION}" --instance-ids "${terminatable[@]}" >/dev/null
  aws ec2 wait instance-terminated --region "${AWS_REGION}" --instance-ids "${terminatable[@]}"
  echo "[+] Cluster instances terminated."
  echo "    A fresh ./scripts/ec2_k8s/setup_ec2.sh -b create can now launch a new deployment."
}

delete_stack_if_present() {
  local stack_name="$1"
  local status

  if ! aws cloudformation describe-stacks \
    --region "${AWS_REGION}" \
    --stack-name "${stack_name}" >/dev/null 2>&1; then
    echo "[*] CloudFormation stack not found: ${stack_name}"
    return 0
  fi

  status="$(aws cloudformation describe-stacks \
    --region "${AWS_REGION}" \
    --stack-name "${stack_name}" \
    --query 'Stacks[0].StackStatus' \
    --output text)"

  if [[ "${status}" == "DELETE_IN_PROGRESS" ]]; then
    echo "[*] Waiting for stack deletion already in progress: ${stack_name}"
    aws cloudformation wait stack-delete-complete \
      --region "${AWS_REGION}" \
      --stack-name "${stack_name}"
    echo "[+] Stack deleted: ${stack_name}"
    return 0
  fi

  echo "[*] Deleting CloudFormation stack: ${stack_name}"
  aws cloudformation delete-stack --region "${AWS_REGION}" --stack-name "${stack_name}"
  aws cloudformation wait stack-delete-complete \
    --region "${AWS_REGION}" \
    --stack-name "${stack_name}"
  echo "[+] Stack deleted: ${stack_name}"
}

resolve_requested_s3_buckets() {
  local bucket
  local env_bucket

  if [[ -n "${LAMBDA_S3_BUCKETS:-}" ]]; then
    for env_bucket in ${LAMBDA_S3_BUCKETS}; do
      append_s3_bucket "${env_bucket}"
    done
  fi

  if [[ -n "${APP_S3_BUCKETS:-}" ]]; then
    for env_bucket in ${APP_S3_BUCKETS}; do
      append_s3_bucket "${env_bucket}"
    done
  fi

  if [[ "${DELETE_SAM_MANAGED_BUCKET}" != "true" ]]; then
    return 0
  fi

  bucket="$(
    aws cloudformation describe-stacks \
      --region "${AWS_REGION}" \
      --stack-name "${SAM_MANAGED_STACK_NAME}" \
      --query "Stacks[0].Outputs[?OutputKey=='SourceBucket'].OutputValue | [0]" \
      --output text 2>/dev/null || true
  )"

  if [[ -z "${bucket}" || "${bucket}" == "None" ]]; then
    echo "[*] SAM-managed artifact bucket not found in stack: ${SAM_MANAGED_STACK_NAME}"
    return 0
  fi

  append_s3_bucket "${bucket}"
}

delete_bucket_if_present() {
  local bucket="$1"
  local versions_json
  local delete_payload
  local object_count

  if ! aws s3api head-bucket --bucket "${bucket}" >/dev/null 2>&1; then
    echo "[*] S3 bucket not found or not accessible: ${bucket}"
    return 0
  fi

  echo "[*] Emptying S3 bucket: s3://${bucket}"
  aws s3 rm "s3://${bucket}" --recursive >/dev/null 2>&1 || true

  while :; do
    versions_json="$(aws s3api list-object-versions --bucket "${bucket}" --output json)"
    object_count="$(printf '%s' "${versions_json}" | jq '((.Versions // []) + (.DeleteMarkers // [])) | length')"
    if [[ "${object_count}" == "0" ]]; then
      break
    fi

    delete_payload="$(printf '%s' "${versions_json}" | jq -c '{
      Objects: (((.Versions // []) + (.DeleteMarkers // [])) | map({Key: .Key, VersionId: .VersionId})),
      Quiet: true
    }')"

    aws s3api delete-objects \
      --bucket "${bucket}" \
      --delete "${delete_payload}" >/dev/null
  done

  aws s3api delete-bucket --bucket "${bucket}" >/dev/null
  echo "[+] Deleted S3 bucket: ${bucket}"
}

teardown_lambda() {
  resolve_stack_name
  resolve_requested_s3_buckets

  echo "[*] Lambda stack: ${STACK_NAME}"
  if [[ ${#S3_BUCKETS[@]} -gt 0 ]]; then
    echo "[*] S3 cleanup: ${S3_BUCKETS[*]}"
  else
    echo "[*] S3 cleanup: none requested"
  fi

  delete_stack_if_present "${STACK_NAME}"

  for bucket in "${S3_BUCKETS[@]}"; do
    delete_bucket_if_present "${bucket}"
  done
}

load_cluster_env

case "${MODE}" in
  cluster)
    confirm "Terminate the EC2 cluster instances from ${CLUSTER_ENV}?"
    terminate_cluster_instances
    ;;
  lambda)
    resolve_stack_name
    resolve_requested_s3_buckets
    if [[ ${#S3_BUCKETS[@]} -gt 0 ]]; then
      confirm "Delete Lambda stack ${STACK_NAME} and requested S3 buckets?"
    else
      confirm "Delete Lambda stack ${STACK_NAME}?"
    fi
    teardown_lambda
    ;;
  both)
    resolve_stack_name
    resolve_requested_s3_buckets
    if [[ ${#S3_BUCKETS[@]} -gt 0 ]]; then
      confirm "Delete Lambda stack ${STACK_NAME}, clean requested S3 buckets, and terminate the EC2 cluster?"
    else
      confirm "Delete Lambda stack ${STACK_NAME} and terminate the EC2 cluster?"
    fi
    teardown_lambda
    terminate_cluster_instances
    ;;
esac
