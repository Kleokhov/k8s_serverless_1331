#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/deploy_lambda_scheduler.sh [options]

Deploys the Lambda scheduler, dispatcher, and supported controllers against an
existing Lambda apiserver kubeconfig stored in SSM.

Options:
  --no-kick       Do not enqueue the initial dispatcher self-trigger.
  --skip-build    Reuse the existing SAM build directory and only deploy.
  --artifact-bucket NAME
                  S3 bucket for SAM deployment artifacts.
  -h, --help      Show help.

Environment knobs:
  AWS_REGION                  AWS region (default: us-east-1)
  SERVERLESS_RESOURCE_PREFIX  Shared prefix for serverless resources
  SCHEDULER_STACK_NAME        CloudFormation stack name
  SCHEDULER_RESOURCE_PREFIX   Scheduler Lambda/SQS/Dynamo resource prefix
  KUBECONFIG_PARAMETER_NAME   SSM parameter containing the full kubeconfig
  SCHEDULER_ATTACH_TO_VPC     true|false, default false
  SCHEDULER_ARTIFACT_BUCKET   S3 bucket for scheduler/controller SAM artifacts
EOF
}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1"
    exit 1
  }
}

KICK_DISPATCHER=1
SKIP_BUILD=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-kick) KICK_DISPATCHER=0; shift ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --artifact-bucket) SCHEDULER_ARTIFACT_BUCKET="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

need aws
need sam

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_LOCAL_DIR="${REPO_LOCAL_DIR:-$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel 2>/dev/null || (cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd))}"
OUT_DIR="${OUT_DIR:-${REPO_LOCAL_DIR}/_serverless_out}"

AWS_REGION="${AWS_REGION:-us-east-1}"
TAG_PREFIX="${TAG_PREFIX:-ctrlless}"
SERVERLESS_RESOURCE_PREFIX="${SERVERLESS_RESOURCE_PREFIX:-${TAG_PREFIX}-serverless}"
SCHEDULER_RESOURCE_PREFIX="${SCHEDULER_RESOURCE_PREFIX:-${SERVERLESS_RESOURCE_PREFIX}-lambda}"
SCHEDULER_STACK_NAME="${SCHEDULER_STACK_NAME:-${SCHEDULER_RESOURCE_PREFIX}}"
PROJECT_TAG_VALUE="${PROJECT_TAG_VALUE:-masters-thesis-lambda-ctrl}"
ENVIRONMENT_TAG_VALUE="${ENVIRONMENT_TAG_VALUE:-thesis}"
KUBECONFIG_PARAMETER_NAME="${KUBECONFIG_PARAMETER_NAME:-/${SERVERLESS_RESOURCE_PREFIX}/admin-kubeconfig}"
SCHEDULER_TEMPLATE="${SCHEDULER_TEMPLATE:-${REPO_LOCAL_DIR}/lambda/template.yaml}"
SCHEDULER_ATTACH_TO_VPC="${SCHEDULER_ATTACH_TO_VPC:-false}"
CREATE_VPC_ENDPOINTS="${CREATE_VPC_ENDPOINTS:-false}"

CLUSTER_VPC_ID="${CLUSTER_VPC_ID:-}"
CLUSTER_SUBNET_IDS="${CLUSTER_SUBNET_IDS:-}"
CLUSTER_SECURITY_GROUP_ID="${CLUSTER_SECURITY_GROUP_ID:-}"
CLUSTER_ROUTE_TABLE_IDS="${CLUSTER_ROUTE_TABLE_IDS:-}"

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

ensure_artifact_bucket() {
  local bucket="$1"
  local head_output

  if head_output="$(aws s3api head-bucket --region "${AWS_REGION}" --bucket "${bucket}" 2>&1)"; then
    echo "[*] Reusing SAM artifact bucket: s3://${bucket}"
    return 0
  fi

  if printf '%s' "${head_output}" | grep -Eq '\(404\)|Not Found|NoSuchBucket'; then
    echo "[*] Creating SAM artifact bucket: s3://${bucket}"
    if [[ "${AWS_REGION}" == "us-east-1" ]]; then
      aws s3api create-bucket \
        --region "${AWS_REGION}" \
        --bucket "${bucket}" >/dev/null
    else
      aws s3api create-bucket \
        --region "${AWS_REGION}" \
        --bucket "${bucket}" \
        --create-bucket-configuration "LocationConstraint=${AWS_REGION}" >/dev/null
    fi
    aws s3api wait bucket-exists --region "${AWS_REGION}" --bucket "${bucket}"
    aws s3api put-public-access-block \
      --region "${AWS_REGION}" \
      --bucket "${bucket}" \
      --public-access-block-configuration \
        BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true >/dev/null
    return 0
  fi

  echo "Cannot access S3 bucket ${bucket}."
  echo "${head_output}"
  echo "Set SCHEDULER_ARTIFACT_BUCKET to a bucket name you own, or delete/rename the conflicting bucket."
  exit 1
}

stack_status() {
  local stack_name="$1"

  aws cloudformation describe-stacks \
    --region "${AWS_REGION}" \
    --stack-name "${stack_name}" \
    --query 'Stacks[0].StackStatus' \
    --output text 2>/dev/null || true
}

find_companion_stacks() {
  local stack_name="$1"
  aws cloudformation list-stacks \
    --region "${AWS_REGION}" \
    --stack-status-filter \
      CREATE_IN_PROGRESS CREATE_FAILED CREATE_COMPLETE \
      ROLLBACK_IN_PROGRESS ROLLBACK_FAILED ROLLBACK_COMPLETE \
      DELETE_IN_PROGRESS DELETE_FAILED \
      UPDATE_IN_PROGRESS UPDATE_COMPLETE_CLEANUP_IN_PROGRESS UPDATE_COMPLETE \
      UPDATE_ROLLBACK_IN_PROGRESS UPDATE_ROLLBACK_FAILED \
      UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS UPDATE_ROLLBACK_COMPLETE \
    --query "StackSummaries[?starts_with(StackName, \`${stack_name}-\`) && ends_with(StackName, \`-CompanionStack\`)].StackName" \
    --output text 2>/dev/null || true
}

ensure_companion_stacks_deployable() {
  local stack_name="$1"
  local companion status

  while IFS= read -r companion; do
    [[ -z "${companion}" ]] && continue
    status="$(stack_status "${companion}")"
    case "${status}" in
      ROLLBACK_COMPLETE|ROLLBACK_FAILED|CREATE_FAILED|DELETE_FAILED)
        echo "[!] Companion stack ${companion} is ${status}; deleting before redeploy"
        aws cloudformation delete-stack \
          --region "${AWS_REGION}" \
          --stack-name "${companion}"
        aws cloudformation wait stack-delete-complete \
          --region "${AWS_REGION}" \
          --stack-name "${companion}"
        ;;
      DELETE_IN_PROGRESS)
        echo "[*] Waiting for companion stack delete to complete: ${companion}"
        aws cloudformation wait stack-delete-complete \
          --region "${AWS_REGION}" \
          --stack-name "${companion}"
        ;;
    esac
  done < <(find_companion_stacks "${stack_name}" | tr '\t' '\n')
}

ensure_deployable_stack() {
  local stack_name="$1"
  local status

  ensure_companion_stacks_deployable "${stack_name}"

  status="$(stack_status "${stack_name}")"
  [[ -z "${status}" || "${status}" == "None" ]] && return 0

  case "${status}" in
    ROLLBACK_COMPLETE|ROLLBACK_FAILED|CREATE_FAILED|DELETE_FAILED)
      echo "[!] Stack ${stack_name} is ${status}; deleting failed stack before redeploy"
      aws cloudformation delete-stack \
        --region "${AWS_REGION}" \
        --stack-name "${stack_name}"
      aws cloudformation wait stack-delete-complete \
        --region "${AWS_REGION}" \
        --stack-name "${stack_name}"
      ;;
    DELETE_IN_PROGRESS)
      echo "[*] Waiting for stack delete to complete: ${stack_name}"
      aws cloudformation wait stack-delete-complete \
        --region "${AWS_REGION}" \
        --stack-name "${stack_name}"
      ;;
  esac
}

print_stack_failure_events() {
  local stack_name="$1"
  local stack_id

  stack_id="$(
    aws cloudformation list-stacks \
      --region "${AWS_REGION}" \
      --query "StackSummaries[?StackName==\`${stack_name}\`] | sort_by(@, &CreationTime)[-1].StackId" \
      --output text 2>/dev/null || true
  )"

  echo
  echo "[!] Recent CloudFormation failure events for ${stack_name}:"
  if [[ -z "${stack_id}" || "${stack_id}" == "None" ]]; then
    echo "    (no stack history found for ${stack_name})"
    return 0
  fi

  aws cloudformation describe-stack-events \
    --region "${AWS_REGION}" \
    --stack-name "${stack_id}" \
    --max-items 40 \
    --query "StackEvents[?contains(ResourceStatus, 'FAILED') || contains(ResourceStatus, 'ROLLBACK')].[Timestamp,LogicalResourceId,ResourceStatus,ResourceStatusReason]" \
    --output table || true
}

AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-$(aws sts get-caller-identity --query 'Account' --output text)}"
SCHEDULER_ARTIFACT_BUCKET="${SCHEDULER_ARTIFACT_BUCKET:-$(default_artifact_bucket_name lambda-controllers)}"

mkdir -p "${OUT_DIR}"

echo "== lambda scheduler/dispatcher/controllers =="
echo "Region:              ${AWS_REGION}"
echo "Stack:               ${SCHEDULER_STACK_NAME}"
echo "Resource prefix:     ${SCHEDULER_RESOURCE_PREFIX}"
echo "Kubeconfig SSM name: ${KUBECONFIG_PARAMETER_NAME}"
echo "Attach to VPC:       ${SCHEDULER_ATTACH_TO_VPC}"
echo "Artifact bucket:     ${SCHEDULER_ARTIFACT_BUCKET}"
echo "Skip build:          ${SKIP_BUILD}"
echo "Out dir:             ${OUT_DIR}"
echo

[[ -f "${SCHEDULER_TEMPLATE}" ]] || { echo "Missing scheduler template: ${SCHEDULER_TEMPLATE}"; exit 1; }

echo "[*] Checking kubeconfig SSM parameter"
aws ssm get-parameter \
  --region "${AWS_REGION}" \
  --name "${KUBECONFIG_PARAMETER_NAME}" \
  --query 'Parameter.Name' \
  --output text >/dev/null

built_template="${OUT_DIR}/.aws-sam-scheduler/template.yaml"
if [[ "${SKIP_BUILD}" == "1" ]]; then
  [[ -f "${built_template}" ]] || {
    echo "Missing built SAM template: ${built_template}"
    echo "Run once without --skip-build first, or set OUT_DIR to the directory that contains .aws-sam-scheduler."
    exit 1
  }
  echo "[*] Skipping SAM build; reusing ${built_template}"
else
  echo "[*] Building Lambda scheduler/dispatcher/controller stack"
  sam build \
    --build-in-source \
    --template-file "${SCHEDULER_TEMPLATE}" \
    --build-dir "${OUT_DIR}/.aws-sam-scheduler"
fi

echo "[*] Deploying Lambda scheduler/dispatcher/controller stack"
ensure_artifact_bucket "${SCHEDULER_ARTIFACT_BUCKET}"
ensure_deployable_stack "${SCHEDULER_STACK_NAME}"
param_overrides=(
  "ResourcePrefix=${SCHEDULER_RESOURCE_PREFIX}"
  "ProjectTagValue=${PROJECT_TAG_VALUE}"
  "EnvironmentTagValue=${ENVIRONMENT_TAG_VALUE}"
  "AttachToVpc=${SCHEDULER_ATTACH_TO_VPC}"
  "CreateVpcEndpoints=${CREATE_VPC_ENDPOINTS}"
  "KubeconfigParameterName=${KUBECONFIG_PARAMETER_NAME}"
)
if [[ "${SCHEDULER_ATTACH_TO_VPC}" == "true" ]]; then
  param_overrides+=(
    "ClusterVpcId=${CLUSTER_VPC_ID}"
    "ClusterSubnetIds=${CLUSTER_SUBNET_IDS}"
    "ClusterSecurityGroupId=${CLUSTER_SECURITY_GROUP_ID}"
    "ClusterRouteTableIds=${CLUSTER_ROUTE_TABLE_IDS}"
  )
fi

if ! sam deploy \
    --template-file "${built_template}" \
    --stack-name "${SCHEDULER_STACK_NAME}" \
    --region "${AWS_REGION}" \
    --capabilities CAPABILITY_IAM \
    --s3-bucket "${SCHEDULER_ARTIFACT_BUCKET}" \
    --disable-rollback \
    --no-confirm-changeset \
    --no-fail-on-empty-changeset \
    --parameter-overrides "${param_overrides[@]}"; then
  print_stack_failure_events "${SCHEDULER_STACK_NAME}"
  exit 1
fi

if [[ "${KICK_DISPATCHER}" == "1" ]]; then
  dispatcher_queue_url="$(
    aws cloudformation describe-stacks \
      --region "${AWS_REGION}" \
      --stack-name "${SCHEDULER_STACK_NAME}" \
      --query "Stacks[0].Outputs[?OutputKey=='DispatcherSelfTriggerQueueUrl'].OutputValue | [0]" \
      --output text
  )"
  if [[ -n "${dispatcher_queue_url}" && "${dispatcher_queue_url}" != "None" ]]; then
    echo "[*] Sending initial dispatcher self-trigger"
    aws sqs send-message \
      --region "${AWS_REGION}" \
      --queue-url "${dispatcher_queue_url}" \
      --message-body tick >/dev/null
  else
    echo "Warning: dispatcher queue URL not found; skipping initial self-trigger"
  fi
fi

echo
echo "Lambda scheduler pipeline deployed."
echo "  stack: ${SCHEDULER_STACK_NAME}"
echo "  ssm:   ${KUBECONFIG_PARAMETER_NAME}"
