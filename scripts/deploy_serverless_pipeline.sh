#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/deploy_serverless_pipeline.sh [options] [-- kubelet-options...]

Deploys the full serverless control plane path:
  1. Lambda kube-apiserver backed by DynamoDB.
  2. A full kubeconfig for that apiserver into SSM.
  3. Lambda scheduler/dispatcher/controller functions.
  4. Serverless kubelet workers.

Options:
  --skip-seed              Do not create default Kubernetes namespaces.
  --skip-dynamo            Do not precreate DynamoDB tables.
  --skip-scheduler         Do not deploy the Lambda scheduler stack.
  --skip-kubelets          Do not create/bootstrap serverless kubelet workers.
  --no-kick                Do not enqueue the initial dispatcher self-trigger.
  -w, --workers N          Number of workers to create (passed to kubelet deploy).
  -b, --behavior MODE      CREATE or REPLACE worker instances (passed through).
  --host HOST              Existing worker public DNS/IP. Repeatable.
  --cluster-env PATH       Source worker hosts from an env file.
  --skip-provision         Do not create EC2 instances; use --host/--cluster-env.
  -i, --identity-file PATH SSH private key for worker bootstrap.
  --user USER              SSH user for worker bootstrap.
  --instance-type TYPE     EC2 worker instance type.
  --root-volume-gb GB      EC2 worker root EBS size.
  --node-prefix PREFIX     Worker node name prefix.
  --node-name NAME         Node name for a single worker host.
  --skip-kubelet-build     Reuse an existing kubelet/kubectl tarball.
  --bins-tar PATH          Tarball containing kubelet and kubectl.
  --apiserver-artifact-bucket NAME
                          S3 bucket for apiserver SAM deployment artifacts.
  --scheduler-artifact-bucket NAME
                          S3 bucket for scheduler/controller SAM artifacts.
  -h, --help               Show help.

Use "-- kubelet-options..." to pass any additional options directly to
scripts/deploy_serverless_kubelet.sh.

Environment knobs:
  AWS_REGION                  AWS region (default: us-east-1)
  TAG_PREFIX                  Base name prefix (default: ctrlless)
  SERVERLESS_RESOURCE_PREFIX  Shared serverless prefix (default: TAG_PREFIX-serverless)
  APISERVER_STACK_NAME        CloudFormation stack for apiserver
  SCHEDULER_STACK_NAME        CloudFormation stack for scheduler
  APISERVER_RESOURCE_PREFIX   Lambda/API resource prefix
  SCHEDULER_RESOURCE_PREFIX   Scheduler Lambda/SQS/Dynamo prefix
  APISERVER_DYNAMO_TABLE      Apiserver DynamoDB base table prefix
  KUBECONFIG_PARAMETER_NAME   SSM parameter containing the full kubeconfig
  APISERVER_ARTIFACT_BUCKET   S3 bucket for apiserver SAM artifacts
  SCHEDULER_ARTIFACT_BUCKET   S3 bucket for scheduler/controller SAM artifacts
  SCHEDULER_ATTACH_TO_VPC     true|false, default false

All environment knobs accepted by the component deploy scripts still apply.
EOF
}

flag_label() {
  if [[ "$1" == "1" ]]; then
    echo "yes"
  else
    echo "no"
  fi
}

DEPLOY_SCHEDULER=1
DEPLOY_KUBELETS=1
SEED_CLUSTER_OBJECTS=1
KICK_DISPATCHER=1
PRECREATE_DYNAMO=1
KUBELET_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-seed) SEED_CLUSTER_OBJECTS=0; shift ;;
    --skip-dynamo) PRECREATE_DYNAMO=0; shift ;;
    --skip-scheduler) DEPLOY_SCHEDULER=0; shift ;;
    --skip-kubelet|--skip-kubelets) DEPLOY_KUBELETS=0; shift ;;
    --no-kick) KICK_DISPATCHER=0; shift ;;
    -w|--workers) KUBELET_ARGS+=("$1" "$2"); shift 2 ;;
    -b|--behavior) KUBELET_ARGS+=("$1" "$2"); shift 2 ;;
    --host) KUBELET_ARGS+=("$1" "$2"); shift 2 ;;
    --cluster-env) KUBELET_ARGS+=("$1" "$2"); shift 2 ;;
    --skip-provision) KUBELET_ARGS+=("$1"); shift ;;
    -i|--identity-file) KUBELET_ARGS+=("$1" "$2"); shift 2 ;;
    --user) KUBELET_ARGS+=("$1" "$2"); shift 2 ;;
    --instance-type) KUBELET_ARGS+=("$1" "$2"); shift 2 ;;
    --root-volume-gb) KUBELET_ARGS+=("$1" "$2"); shift 2 ;;
    --node-prefix) KUBELET_ARGS+=("$1" "$2"); shift 2 ;;
    --node-name) KUBELET_ARGS+=("$1" "$2"); shift 2 ;;
    --skip-kubelet-build) KUBELET_ARGS+=(--skip-build); shift ;;
    --bins-tar) KUBELET_ARGS+=("$1" "$2"); shift 2 ;;
    --apiserver-artifact-bucket) APISERVER_ARTIFACT_BUCKET="$2"; shift 2 ;;
    --scheduler-artifact-bucket) SCHEDULER_ARTIFACT_BUCKET="$2"; shift 2 ;;
    --)
      shift
      KUBELET_ARGS+=("$@")
      break
      ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_LOCAL_DIR="${REPO_LOCAL_DIR:-$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel 2>/dev/null || (cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd))}"
K8S_DIR="${K8S_DIR:-${REPO_LOCAL_DIR}/kubernetes}"
OUT_DIR="${OUT_DIR:-${REPO_LOCAL_DIR}/_serverless_out}"

AWS_REGION="${AWS_REGION:-us-east-1}"
TAG_PREFIX="${TAG_PREFIX:-ctrlless}"
SERVERLESS_RESOURCE_PREFIX="${SERVERLESS_RESOURCE_PREFIX:-${TAG_PREFIX}-serverless}"
APISERVER_RESOURCE_PREFIX="${APISERVER_RESOURCE_PREFIX:-${SERVERLESS_RESOURCE_PREFIX}-apiserver}"
SCHEDULER_RESOURCE_PREFIX="${SCHEDULER_RESOURCE_PREFIX:-${SERVERLESS_RESOURCE_PREFIX}-lambda}"
APISERVER_STACK_NAME="${APISERVER_STACK_NAME:-${APISERVER_RESOURCE_PREFIX}}"
SCHEDULER_STACK_NAME="${SCHEDULER_STACK_NAME:-${SCHEDULER_RESOURCE_PREFIX}}"
APISERVER_DYNAMO_TABLE="${APISERVER_DYNAMO_TABLE:-${APISERVER_RESOURCE_PREFIX}}"
KUBECONFIG_PARAMETER_NAME="${KUBECONFIG_PARAMETER_NAME:-/${SERVERLESS_RESOURCE_PREFIX}/admin-kubeconfig}"
KUBECONFIG_PATH="${KUBECONFIG_PATH:-${OUT_DIR}/lambda-apiserver.kubeconfig}"
WORKER_ENV="${WORKER_ENV:-${OUT_DIR}/workers.env}"
APISERVER_ARTIFACT_BUCKET="${APISERVER_ARTIFACT_BUCKET:-}"
SCHEDULER_ARTIFACT_BUCKET="${SCHEDULER_ARTIFACT_BUCKET:-}"

APISERVER_TEMPLATE="${APISERVER_TEMPLATE:-${REPO_LOCAL_DIR}/lambda/template.apiserver.yaml}"
SCHEDULER_TEMPLATE="${SCHEDULER_TEMPLATE:-${REPO_LOCAL_DIR}/lambda/template.yaml}"
PRECREATE_DYNAMO_TABLES_SCRIPT="${PRECREATE_DYNAMO_TABLES_SCRIPT:-${SCRIPT_DIR}/precreate_dynamo_tables.sh}"
SEED_APISERVER_SCRIPT="${SEED_APISERVER_SCRIPT:-${SCRIPT_DIR}/seed_lambda_apiserver_raw.sh}"
DYNAMO_INIT_APISERVER_DIR="${DYNAMO_INIT_APISERVER_DIR:-${K8S_DIR}/staging/src/k8s.io/apiserver}"

DEPLOY_LAMBDA_APISERVER_SCRIPT="${DEPLOY_LAMBDA_APISERVER_SCRIPT:-${SCRIPT_DIR}/deploy_lambda_apiserver.sh}"
DEPLOY_LAMBDA_SCHEDULER_SCRIPT="${DEPLOY_LAMBDA_SCHEDULER_SCRIPT:-${SCRIPT_DIR}/deploy_lambda_scheduler.sh}"
DEPLOY_SERVERLESS_KUBELET_SCRIPT="${DEPLOY_SERVERLESS_KUBELET_SCRIPT:-${SCRIPT_DIR}/deploy_serverless_kubelet.sh}"

export REPO_LOCAL_DIR K8S_DIR OUT_DIR
export AWS_REGION SERVERLESS_RESOURCE_PREFIX
export APISERVER_RESOURCE_PREFIX SCHEDULER_RESOURCE_PREFIX
export APISERVER_STACK_NAME SCHEDULER_STACK_NAME APISERVER_DYNAMO_TABLE
export KUBECONFIG_PARAMETER_NAME KUBECONFIG_PATH WORKER_ENV
export APISERVER_ARTIFACT_BUCKET SCHEDULER_ARTIFACT_BUCKET
export APISERVER_TEMPLATE SCHEDULER_TEMPLATE PRECREATE_DYNAMO_TABLES_SCRIPT
export SEED_APISERVER_SCRIPT DYNAMO_INIT_APISERVER_DIR

mkdir -p "${OUT_DIR}"

[[ -x "${DEPLOY_LAMBDA_APISERVER_SCRIPT}" ]] || { echo "Missing executable apiserver deploy script: ${DEPLOY_LAMBDA_APISERVER_SCRIPT}"; exit 1; }
[[ -x "${DEPLOY_LAMBDA_SCHEDULER_SCRIPT}" ]] || { echo "Missing executable scheduler deploy script: ${DEPLOY_LAMBDA_SCHEDULER_SCRIPT}"; exit 1; }
[[ -x "${DEPLOY_SERVERLESS_KUBELET_SCRIPT}" ]] || { echo "Missing executable kubelet deploy script: ${DEPLOY_SERVERLESS_KUBELET_SCRIPT}"; exit 1; }

echo "== serverless pipeline =="
echo "Region:              ${AWS_REGION}"
echo "Serverless prefix:   ${SERVERLESS_RESOURCE_PREFIX}"
echo "Apiserver stack:     ${APISERVER_STACK_NAME}"
echo "Scheduler stack:     ${SCHEDULER_STACK_NAME}"
echo "Apiserver DDB base:  ${APISERVER_DYNAMO_TABLE}"
echo "Kubeconfig SSM name: ${KUBECONFIG_PARAMETER_NAME}"
echo "Local kubeconfig:    ${KUBECONFIG_PATH}"
echo "Workers env:         ${WORKER_ENV}"
if [[ -n "${APISERVER_ARTIFACT_BUCKET}" ]]; then
  echo "Apiserver artifacts: ${APISERVER_ARTIFACT_BUCKET}"
else
  echo "Apiserver artifacts: component default"
fi
if [[ -n "${SCHEDULER_ARTIFACT_BUCKET}" ]]; then
  echo "Scheduler artifacts: ${SCHEDULER_ARTIFACT_BUCKET}"
else
  echo "Scheduler artifacts: component default"
fi
echo "Deploy scheduler:    $(flag_label "${DEPLOY_SCHEDULER}")"
echo "Deploy kubelets:     $(flag_label "${DEPLOY_KUBELETS}")"
echo "Out dir:             ${OUT_DIR}"
echo

apiserver_args=()
if [[ "${SEED_CLUSTER_OBJECTS}" == "0" ]]; then
  apiserver_args+=(--skip-seed)
fi
if [[ "${PRECREATE_DYNAMO}" == "0" ]]; then
  apiserver_args+=(--skip-dynamo)
fi

echo "[*] Running Lambda apiserver deployment"
"${DEPLOY_LAMBDA_APISERVER_SCRIPT}" "${apiserver_args[@]}"

if [[ "${DEPLOY_SCHEDULER}" == "1" ]]; then
  scheduler_args=()
  if [[ "${KICK_DISPATCHER}" == "0" ]]; then
    scheduler_args+=(--no-kick)
  fi

  echo
  echo "[*] Running Lambda scheduler deployment"
  "${DEPLOY_LAMBDA_SCHEDULER_SCRIPT}" "${scheduler_args[@]}"
fi

if [[ "${DEPLOY_KUBELETS}" == "1" ]]; then
  echo
  echo "[*] Running serverless kubelet deployment"
  TAG_PREFIX="${SERVERLESS_RESOURCE_PREFIX}" "${DEPLOY_SERVERLESS_KUBELET_SCRIPT}" "${KUBELET_ARGS[@]}"
fi

echo
echo "Serverless pipeline deployed."
echo "  apiserver stack: ${APISERVER_STACK_NAME}"
echo "  scheduler stack: ${SCHEDULER_STACK_NAME}"
echo "  kubeconfig:      ${KUBECONFIG_PATH}"
echo "  ssm:             ${KUBECONFIG_PARAMETER_NAME}"
if [[ "${DEPLOY_KUBELETS}" == "1" ]]; then
  echo "  workers env:     ${WORKER_ENV}"
fi
