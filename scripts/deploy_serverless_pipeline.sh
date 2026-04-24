#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/deploy_serverless_pipeline.sh [options]

Deploys:
  1. Lambda kube-apiserver backed by DynamoDB.
  2. A full kubeconfig for that apiserver into SSM.
  3. The Lambda scheduler/dispatcher stack pointed at that kubeconfig.
  4. Optional seed Namespaces/Nodes for a minimal scheduling surface.

Options:
  --skip-scheduler       Deploy only the Lambda apiserver and kubeconfig.
  --skip-seed            Do not create default namespaces or synthetic nodes.
  --skip-dynamo          Do not precreate DynamoDB tables.
  --no-kick              Do not enqueue the initial dispatcher self-trigger.
  --seed-nodes N         Number of synthetic Node objects to create (default: 1).
  -h, --help             Show help.

Environment knobs:
  AWS_REGION                  AWS region (default: us-east-1)
  TAG_PREFIX                  Name prefix (default: ctrlless)
  APISERVER_STACK_NAME        CloudFormation stack for apiserver
  SCHEDULER_STACK_NAME        CloudFormation stack for scheduler
  APISERVER_RESOURCE_PREFIX   Lambda/API resource prefix
  SCHEDULER_RESOURCE_PREFIX   Scheduler Lambda/SQS/Dynamo prefix
  APISERVER_DYNAMO_TABLE      Apiserver DynamoDB base table prefix
  SCHEDULER_ATTACH_TO_VPC     true|false, default false for full serverless
  DYNAMO_INIT_APISERVER_DIR   Module containing tools/init-dynamo-tables
EOF
}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1"
    exit 1
  }
}

DEPLOY_SCHEDULER=1
SEED_CLUSTER_OBJECTS=1
KICK_DISPATCHER=1
PRECREATE_DYNAMO=1
SEED_NODES="${SEED_NODES:-1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-scheduler) DEPLOY_SCHEDULER=0; shift ;;
    --skip-seed) SEED_CLUSTER_OBJECTS=0; shift ;;
    --skip-dynamo) PRECREATE_DYNAMO=0; shift ;;
    --no-kick) KICK_DISPATCHER=0; shift ;;
    --seed-nodes) SEED_NODES="$2"; shift 2 ;;
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
K8S_DIR="${K8S_DIR:-${REPO_LOCAL_DIR}/kubernetes}"
OUT_DIR="${OUT_DIR:-${REPO_LOCAL_DIR}/_serverless_out}"

AWS_REGION="${AWS_REGION:-us-east-1}"
TAG_PREFIX="${TAG_PREFIX:-ctrlless}"
APISERVER_RESOURCE_PREFIX="${APISERVER_RESOURCE_PREFIX:-${TAG_PREFIX}-apiserver}"
SCHEDULER_RESOURCE_PREFIX="${SCHEDULER_RESOURCE_PREFIX:-${TAG_PREFIX}-lambda}"
APISERVER_STACK_NAME="${APISERVER_STACK_NAME:-${APISERVER_RESOURCE_PREFIX}}"
SCHEDULER_STACK_NAME="${SCHEDULER_STACK_NAME:-${SCHEDULER_RESOURCE_PREFIX}}"
APISERVER_DYNAMO_TABLE="${APISERVER_DYNAMO_TABLE:-${APISERVER_RESOURCE_PREFIX}}"
SERVICE_CLUSTER_IP_RANGE="${SERVICE_CLUSTER_IP_RANGE:-10.96.0.0/12}"
APISERVER_ADVERTISE_ADDRESS="${APISERVER_ADVERTISE_ADDRESS:-127.0.0.1}"
APISERVER_BIND_ADDRESS="${APISERVER_BIND_ADDRESS:-127.0.0.1}"
PROJECT_TAG_VALUE="${PROJECT_TAG_VALUE:-masters-thesis-lambda-ctrl}"
ENVIRONMENT_TAG_VALUE="${ENVIRONMENT_TAG_VALUE:-thesis}"
APISERVER_TOKEN="${APISERVER_TOKEN:-devtoken123}"
KUBECONFIG_PARAMETER_NAME="${KUBECONFIG_PARAMETER_NAME:-/${SCHEDULER_RESOURCE_PREFIX}/admin-kubeconfig}"
APISERVER_LOG_TAIL_SINCE="${APISERVER_LOG_TAIL_SINCE:-5m}"
APISERVER_LOG_TAIL_DELAY="${APISERVER_LOG_TAIL_DELAY:-3}"
SCHEDULER_ATTACH_TO_VPC="${SCHEDULER_ATTACH_TO_VPC:-false}"
CREATE_VPC_ENDPOINTS="${CREATE_VPC_ENDPOINTS:-false}"

CLUSTER_VPC_ID="${CLUSTER_VPC_ID:-}"
CLUSTER_SUBNET_IDS="${CLUSTER_SUBNET_IDS:-}"
CLUSTER_SECURITY_GROUP_ID="${CLUSTER_SECURITY_GROUP_ID:-}"
CLUSTER_ROUTE_TABLE_IDS="${CLUSTER_ROUTE_TABLE_IDS:-}"

APISERVER_TEMPLATE="${APISERVER_TEMPLATE:-${REPO_LOCAL_DIR}/lambda/template.apiserver.yaml}"
SCHEDULER_TEMPLATE="${SCHEDULER_TEMPLATE:-${REPO_LOCAL_DIR}/lambda/template.yaml}"
PRECREATE_DYNAMO_TABLES_SCRIPT="${PRECREATE_DYNAMO_TABLES_SCRIPT:-${SCRIPT_DIR}/precreate_dynamo_tables.sh}"
DYNAMO_INIT_APISERVER_DIR="${DYNAMO_INIT_APISERVER_DIR:-${K8S_DIR}/staging/src/k8s.io/apiserver}"
SEED_APISERVER_SCRIPT="${SEED_APISERVER_SCRIPT:-${SCRIPT_DIR}/seed_lambda_apiserver_raw.sh}"

mkdir -p "${OUT_DIR}"

echo "== serverless pipeline =="
echo "Region:              ${AWS_REGION}"
echo "Apiserver stack:     ${APISERVER_STACK_NAME}"
echo "Scheduler stack:     ${SCHEDULER_STACK_NAME}"
echo "Apiserver DDB base:  ${APISERVER_DYNAMO_TABLE}"
echo "Scheduler prefix:    ${SCHEDULER_RESOURCE_PREFIX}"
echo "Kubeconfig SSM name: ${KUBECONFIG_PARAMETER_NAME}"
echo "Out dir:             ${OUT_DIR}"
echo

[[ -f "${APISERVER_TEMPLATE}" ]] || { echo "Missing apiserver template: ${APISERVER_TEMPLATE}"; exit 1; }
[[ -f "${SCHEDULER_TEMPLATE}" ]] || { echo "Missing scheduler template: ${SCHEDULER_TEMPLATE}"; exit 1; }
if [[ "${PRECREATE_DYNAMO}" == "1" ]]; then
  [[ -x "${PRECREATE_DYNAMO_TABLES_SCRIPT}" ]] || { echo "Missing executable table precreate script: ${PRECREATE_DYNAMO_TABLES_SCRIPT}"; exit 1; }
  echo "[*] Precreating apiserver DynamoDB tables"
  DYNAMO_REGION="${AWS_REGION}" \
  DYNAMO_TABLE="${APISERVER_DYNAMO_TABLE}" \
  APISERVER_DIR="${DYNAMO_INIT_APISERVER_DIR}" \
  "${PRECREATE_DYNAMO_TABLES_SCRIPT}"
else
  echo "[*] Skipping DynamoDB table precreate"
fi
if [[ "${SEED_CLUSTER_OBJECTS}" == "1" ]]; then
  [[ -x "${SEED_APISERVER_SCRIPT}" ]] || { echo "Missing executable seed script: ${SEED_APISERVER_SCRIPT}"; exit 1; }
fi

echo "[*] Building Lambda apiserver image"
sam build \
  --template-file "${APISERVER_TEMPLATE}" \
  --build-dir "${OUT_DIR}/.aws-sam-apiserver"

echo "[*] Deploying Lambda apiserver"
sam deploy \
  --template-file "${OUT_DIR}/.aws-sam-apiserver/template.yaml" \
  --stack-name "${APISERVER_STACK_NAME}" \
  --region "${AWS_REGION}" \
  --capabilities CAPABILITY_IAM \
  --resolve-s3 \
  --resolve-image-repos \
  --no-confirm-changeset \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    ResourcePrefix="${APISERVER_RESOURCE_PREFIX}" \
    ProjectTagValue="${PROJECT_TAG_VALUE}" \
    EnvironmentTagValue="${ENVIRONMENT_TAG_VALUE}" \
    DynamoRegion="${AWS_REGION}" \
    DynamoTable="${APISERVER_DYNAMO_TABLE}" \
    ServiceClusterIPRange="${SERVICE_CLUSTER_IP_RANGE}" \
    ApiServerAdvertiseAddress="${APISERVER_ADVERTISE_ADDRESS}" \
    ApiServerBindAddress="${APISERVER_BIND_ADDRESS}"

api_server_url="$(
  aws cloudformation describe-stacks \
    --region "${AWS_REGION}" \
    --stack-name "${APISERVER_STACK_NAME}" \
    --query "Stacks[0].Outputs[?OutputKey=='ApiServerUrl'].OutputValue | [0]" \
    --output text
)"
[[ -n "${api_server_url}" && "${api_server_url}" != "None" ]] || {
  echo "Failed to read ApiServerUrl from stack ${APISERVER_STACK_NAME}"
  exit 1
}

api_server_function_name="$(
  aws cloudformation describe-stacks \
    --region "${AWS_REGION}" \
    --stack-name "${APISERVER_STACK_NAME}" \
    --query "Stacks[0].Outputs[?OutputKey=='ApiServerFunctionName'].OutputValue | [0]" \
    --output text
)"

tail_apiserver_logs() {
  [[ -n "${api_server_function_name}" && "${api_server_function_name}" != "None" ]] || return 0
  echo
  echo "[!] Seed failed; recent Lambda apiserver logs:"
  sleep "${APISERVER_LOG_TAIL_DELAY}"
  aws logs tail "/aws/lambda/${api_server_function_name}" \
    --region "${AWS_REGION}" \
    --since "${APISERVER_LOG_TAIL_SINCE}" \
    --format short || true
}

local_kubeconfig="${OUT_DIR}/lambda-apiserver.kubeconfig"
cat > "${local_kubeconfig}" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: lambda-apiserver
  cluster:
    server: ${api_server_url}
    insecure-skip-tls-verify: true
users:
- name: lambda-user
  user:
    token: ${APISERVER_TOKEN}
contexts:
- name: lambda-user@lambda-apiserver
  context:
    cluster: lambda-apiserver
    user: lambda-user
current-context: lambda-user@lambda-apiserver
EOF

echo "[*] Publishing full kubeconfig to SSM"
aws ssm put-parameter \
  --region "${AWS_REGION}" \
  --name "${KUBECONFIG_PARAMETER_NAME}" \
  --type String \
  --overwrite \
  --value "$(cat "${local_kubeconfig}")" >/dev/null

if [[ "${SEED_CLUSTER_OBJECTS}" == "1" ]]; then
  if ! "${SEED_APISERVER_SCRIPT}" \
    --kubeconfig "${local_kubeconfig}" \
    --namespaces "default,kube-system,kube-public,kube-node-lease" \
    --synthetic-nodes "${SEED_NODES}"; then
    tail_apiserver_logs
    exit 1
  fi
fi

if [[ "${DEPLOY_SCHEDULER}" == "1" ]]; then
  echo "[*] Building Lambda scheduler/dispatcher stack"
  sam build \
    --template-file "${SCHEDULER_TEMPLATE}" \
    --build-dir "${OUT_DIR}/.aws-sam-scheduler"

  echo "[*] Deploying Lambda scheduler/dispatcher stack"
  sam deploy \
    --template-file "${OUT_DIR}/.aws-sam-scheduler/template.yaml" \
    --stack-name "${SCHEDULER_STACK_NAME}" \
    --region "${AWS_REGION}" \
    --capabilities CAPABILITY_IAM \
    --resolve-s3 \
    --no-confirm-changeset \
    --no-fail-on-empty-changeset \
    --parameter-overrides \
      ResourcePrefix="${SCHEDULER_RESOURCE_PREFIX}" \
      ProjectTagValue="${PROJECT_TAG_VALUE}" \
      EnvironmentTagValue="${ENVIRONMENT_TAG_VALUE}" \
      AttachToVpc="${SCHEDULER_ATTACH_TO_VPC}" \
      ClusterVpcId="${CLUSTER_VPC_ID}" \
      ClusterSubnetIds="${CLUSTER_SUBNET_IDS}" \
      ClusterSecurityGroupId="${CLUSTER_SECURITY_GROUP_ID}" \
      ClusterRouteTableIds="${CLUSTER_ROUTE_TABLE_IDS}" \
      CreateVpcEndpoints="${CREATE_VPC_ENDPOINTS}" \
      KubeconfigParameterName="${KUBECONFIG_PARAMETER_NAME}" \
      KubeconfigParameterPrefix=""

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
fi

echo
echo "Serverless control plane pipeline deployed."
echo "  apiserver:  ${api_server_url}"
echo "  kubeconfig: ${local_kubeconfig}"
echo "  ssm:        ${KUBECONFIG_PARAMETER_NAME}"
