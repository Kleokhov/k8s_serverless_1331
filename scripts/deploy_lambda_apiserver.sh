#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/deploy_lambda_apiserver.sh [options]

Deploys the Lambda Kubernetes apiserver, precreates its DynamoDB storage
tables, writes a local kubeconfig, publishes that kubeconfig to SSM, and seeds
the namespaces needed by real kubelets.

Options:
  --skip-seed                 Do not seed default Kubernetes namespaces.
  --skip-dynamo               Do not precreate DynamoDB tables.
  --seed-only                 Use an existing apiserver stack and only publish/seed.
  --seed-synthetic-nodes N    Also create N synthetic Node objects (default: 0).
  -h, --help                  Show help.

Environment knobs:
  AWS_REGION                  AWS region (default: us-east-1)
  SERVERLESS_RESOURCE_PREFIX  Shared prefix for serverless resources
  APISERVER_STACK_NAME        CloudFormation stack name
  APISERVER_RESOURCE_PREFIX   Lambda/API resource prefix
  APISERVER_DYNAMO_TABLE      DynamoDB table prefix
  KUBECONFIG_PARAMETER_NAME   SSM parameter containing the full kubeconfig
  OUT_DIR                     Local output directory
EOF
}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1"
    exit 1
  }
}

SEED_NAMESPACES=1
SEED_SYNTHETIC_NODES="${SEED_SYNTHETIC_NODES:-0}"
PRECREATE_DYNAMO=1
BUILD_DEPLOY_APISERVER=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-seed) SEED_NAMESPACES=0; shift ;;
    --skip-dynamo) PRECREATE_DYNAMO=0; shift ;;
    --seed-only) PRECREATE_DYNAMO=0; BUILD_DEPLOY_APISERVER=0; shift ;;
    --seed-synthetic-nodes) SEED_SYNTHETIC_NODES="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

need aws
if [[ "${BUILD_DEPLOY_APISERVER}" == "1" ]]; then
  need sam
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_LOCAL_DIR="${REPO_LOCAL_DIR:-$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel 2>/dev/null || (cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd))}"
K8S_DIR="${K8S_DIR:-${REPO_LOCAL_DIR}/kubernetes}"
OUT_DIR="${OUT_DIR:-${REPO_LOCAL_DIR}/_serverless_out}"

AWS_REGION="${AWS_REGION:-us-east-1}"
TAG_PREFIX="${TAG_PREFIX:-ctrlless}"
SERVERLESS_RESOURCE_PREFIX="${SERVERLESS_RESOURCE_PREFIX:-${TAG_PREFIX}-serverless}"
APISERVER_RESOURCE_PREFIX="${APISERVER_RESOURCE_PREFIX:-${SERVERLESS_RESOURCE_PREFIX}-apiserver}"
APISERVER_STACK_NAME="${APISERVER_STACK_NAME:-${APISERVER_RESOURCE_PREFIX}}"
APISERVER_DYNAMO_TABLE="${APISERVER_DYNAMO_TABLE:-${APISERVER_RESOURCE_PREFIX}}"
SERVICE_CLUSTER_IP_RANGE="${SERVICE_CLUSTER_IP_RANGE:-10.96.0.0/12}"
APISERVER_ADVERTISE_ADDRESS="${APISERVER_ADVERTISE_ADDRESS:-127.0.0.1}"
APISERVER_BIND_ADDRESS="${APISERVER_BIND_ADDRESS:-127.0.0.1}"
PROJECT_TAG_VALUE="${PROJECT_TAG_VALUE:-masters-thesis-lambda-ctrl}"
ENVIRONMENT_TAG_VALUE="${ENVIRONMENT_TAG_VALUE:-thesis}"
APISERVER_TOKEN="${APISERVER_TOKEN:-devtoken123}"
KUBECONFIG_PARAMETER_NAME="${KUBECONFIG_PARAMETER_NAME:-/${SERVERLESS_RESOURCE_PREFIX}/admin-kubeconfig}"
APISERVER_LOG_TAIL_SINCE="${APISERVER_LOG_TAIL_SINCE:-5m}"
APISERVER_LOG_TAIL_DELAY="${APISERVER_LOG_TAIL_DELAY:-3}"
APISERVER_TEMPLATE="${APISERVER_TEMPLATE:-${REPO_LOCAL_DIR}/lambda/template.apiserver.yaml}"
PRECREATE_DYNAMO_TABLES_SCRIPT="${PRECREATE_DYNAMO_TABLES_SCRIPT:-${SCRIPT_DIR}/precreate_dynamo_tables.sh}"
DYNAMO_INIT_APISERVER_DIR="${DYNAMO_INIT_APISERVER_DIR:-${K8S_DIR}/staging/src/k8s.io/apiserver}"
SEED_APISERVER_SCRIPT="${SEED_APISERVER_SCRIPT:-${SCRIPT_DIR}/seed_lambda_apiserver_raw.sh}"

mkdir -p "${OUT_DIR}"

if [[ "${APISERVER_TOKEN}" != "devtoken123" ]]; then
  echo "Warning: lambda/cmd/apiserver/Dockerfile currently bakes devtoken123 into tokens.csv."
  echo "         Set APISERVER_TOKEN=devtoken123 unless you also rebuild that token file."
fi

echo "== lambda apiserver =="
echo "Region:              ${AWS_REGION}"
echo "Stack:               ${APISERVER_STACK_NAME}"
echo "Resource prefix:     ${APISERVER_RESOURCE_PREFIX}"
echo "DynamoDB base table: ${APISERVER_DYNAMO_TABLE}"
echo "Kubeconfig SSM name: ${KUBECONFIG_PARAMETER_NAME}"
echo "Out dir:             ${OUT_DIR}"
echo

if [[ "${BUILD_DEPLOY_APISERVER}" == "1" ]]; then
  [[ -f "${APISERVER_TEMPLATE}" ]] || { echo "Missing apiserver template: ${APISERVER_TEMPLATE}"; exit 1; }
fi
if [[ "${PRECREATE_DYNAMO}" == "1" ]]; then
  [[ -x "${PRECREATE_DYNAMO_TABLES_SCRIPT}" ]] || { echo "Missing executable table precreate script: ${PRECREATE_DYNAMO_TABLES_SCRIPT}"; exit 1; }
fi
if [[ "${SEED_NAMESPACES}" == "1" || "${SEED_SYNTHETIC_NODES}" != "0" ]]; then
  [[ -x "${SEED_APISERVER_SCRIPT}" ]] || { echo "Missing executable seed script: ${SEED_APISERVER_SCRIPT}"; exit 1; }
fi

if [[ "${PRECREATE_DYNAMO}" == "1" ]]; then
  echo "[*] Precreating apiserver DynamoDB tables"
  DYNAMO_REGION="${AWS_REGION}" \
  DYNAMO_TABLE="${APISERVER_DYNAMO_TABLE}" \
  APISERVER_DIR="${DYNAMO_INIT_APISERVER_DIR}" \
  "${PRECREATE_DYNAMO_TABLES_SCRIPT}"
else
  echo "[*] Skipping DynamoDB table precreate"
fi

if [[ "${BUILD_DEPLOY_APISERVER}" == "1" ]]; then
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
else
  echo "[*] Skipping Lambda apiserver build/deploy; using existing stack ${APISERVER_STACK_NAME}"
fi

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

if [[ "${SEED_NAMESPACES}" == "1" || "${SEED_SYNTHETIC_NODES}" != "0" ]]; then
  namespaces=""
  if [[ "${SEED_NAMESPACES}" == "1" ]]; then
    namespaces="default,kube-system,kube-public,kube-node-lease"
  fi
  if ! "${SEED_APISERVER_SCRIPT}" \
    --kubeconfig "${local_kubeconfig}" \
    --namespaces "${namespaces}" \
    --synthetic-nodes "${SEED_SYNTHETIC_NODES}"; then
    tail_apiserver_logs
    exit 1
  fi
fi

echo
echo "Lambda apiserver deployed."
echo "  apiserver:  ${api_server_url}"
echo "  kubeconfig: ${local_kubeconfig}"
echo "  ssm:        ${KUBECONFIG_PARAMETER_NAME}"
