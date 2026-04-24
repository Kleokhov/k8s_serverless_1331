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
  -h, --help      Show help.

Environment knobs:
  AWS_REGION                  AWS region (default: us-east-1)
  SERVERLESS_RESOURCE_PREFIX  Shared prefix for serverless resources
  SCHEDULER_STACK_NAME        CloudFormation stack name
  SCHEDULER_RESOURCE_PREFIX   Scheduler Lambda/SQS/Dynamo resource prefix
  KUBECONFIG_PARAMETER_NAME   SSM parameter containing the full kubeconfig
  SCHEDULER_ATTACH_TO_VPC     true|false, default false
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

mkdir -p "${OUT_DIR}"

echo "== lambda scheduler/dispatcher/controllers =="
echo "Region:              ${AWS_REGION}"
echo "Stack:               ${SCHEDULER_STACK_NAME}"
echo "Resource prefix:     ${SCHEDULER_RESOURCE_PREFIX}"
echo "Kubeconfig SSM name: ${KUBECONFIG_PARAMETER_NAME}"
echo "Attach to VPC:       ${SCHEDULER_ATTACH_TO_VPC}"
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
  echo "[*] Fixing Go module cache permissions for SAM source copy"
  find "${REPO_LOCAL_DIR}/kubernetes/_output" -type d ! -writable -exec chmod u+w {} \; 2>/dev/null || true

  echo "[*] Building Lambda scheduler/dispatcher/controller stack"
  sam build \
    --template-file "${SCHEDULER_TEMPLATE}" \
    --build-dir "${OUT_DIR}/.aws-sam-scheduler"
fi

echo "[*] Deploying Lambda scheduler/dispatcher/controller stack"
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

sam deploy \
  --template-file "${built_template}" \
  --stack-name "${SCHEDULER_STACK_NAME}" \
  --region "${AWS_REGION}" \
  --capabilities CAPABILITY_IAM \
  --resolve-s3 \
  --no-confirm-changeset \
  --no-fail-on-empty-changeset \
  --parameter-overrides "${param_overrides[@]}"

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
