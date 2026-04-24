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
  --artifact-bucket NAME      S3 bucket for SAM deployment artifacts.
  -h, --help                  Show help.

Environment knobs:
  AWS_REGION                  AWS region (default: us-east-1)
  SERVERLESS_RESOURCE_PREFIX  Shared prefix for serverless resources
  APISERVER_STACK_NAME        CloudFormation stack name
  APISERVER_RESOURCE_PREFIX   Lambda/API resource prefix
  APISERVER_DYNAMO_TABLE      DynamoDB table prefix
  KUBECONFIG_PARAMETER_NAME   SSM parameter containing the full kubeconfig
  APISERVER_ARTIFACT_BUCKET   S3 bucket for apiserver SAM artifacts
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
PRECREATE_DYNAMO=1
BUILD_DEPLOY_APISERVER=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-seed) SEED_NAMESPACES=0; shift ;;
    --skip-dynamo) PRECREATE_DYNAMO=0; shift ;;
    --seed-only) PRECREATE_DYNAMO=0; BUILD_DEPLOY_APISERVER=0; shift ;;
    --artifact-bucket) APISERVER_ARTIFACT_BUCKET="$2"; shift 2 ;;
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
  echo "Set APISERVER_ARTIFACT_BUCKET to a bucket name you own, or delete/rename the conflicting bucket."
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
APISERVER_ARTIFACT_BUCKET="${APISERVER_ARTIFACT_BUCKET:-$(default_artifact_bucket_name lambda-apiserver)}"

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
echo "Artifact bucket:     ${APISERVER_ARTIFACT_BUCKET}"
echo "Out dir:             ${OUT_DIR}"
echo

if [[ "${BUILD_DEPLOY_APISERVER}" == "1" ]]; then
  [[ -f "${APISERVER_TEMPLATE}" ]] || { echo "Missing apiserver template: ${APISERVER_TEMPLATE}"; exit 1; }
fi
if [[ "${PRECREATE_DYNAMO}" == "1" ]]; then
  [[ -x "${PRECREATE_DYNAMO_TABLES_SCRIPT}" ]] || { echo "Missing executable table precreate script: ${PRECREATE_DYNAMO_TABLES_SCRIPT}"; exit 1; }
fi
if [[ "${SEED_NAMESPACES}" == "1" ]]; then
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
  ensure_artifact_bucket "${APISERVER_ARTIFACT_BUCKET}"
  ensure_deployable_stack "${APISERVER_STACK_NAME}"
  if ! sam deploy \
      --template-file "${OUT_DIR}/.aws-sam-apiserver/template.yaml" \
      --stack-name "${APISERVER_STACK_NAME}" \
      --region "${AWS_REGION}" \
      --capabilities CAPABILITY_IAM \
      --s3-bucket "${APISERVER_ARTIFACT_BUCKET}" \
      --resolve-image-repos \
      --disable-rollback \
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
        ApiServerBindAddress="${APISERVER_BIND_ADDRESS}"; then
    print_stack_failure_events "${APISERVER_STACK_NAME}"
    exit 1
  fi
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

if [[ "${SEED_NAMESPACES}" == "1" ]]; then
  if ! "${SEED_APISERVER_SCRIPT}" \
    --kubeconfig "${local_kubeconfig}" \
    --namespaces "default,kube-system,kube-public,kube-node-lease"; then
    tail_apiserver_logs
    exit 1
  fi
fi

echo
echo "Lambda apiserver deployed."
echo "  apiserver:  ${api_server_url}"
echo "  kubeconfig: ${local_kubeconfig}"
echo "  ssm:        ${KUBECONFIG_PARAMETER_NAME}"
