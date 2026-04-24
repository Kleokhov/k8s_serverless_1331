#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/ec2_k8s/setup_ec2.sh [options]

Options:
  -w, --workers N         Number of worker nodes (default: 2)
  -b, --behavior MODE     Cluster lifecycle: create | replace (default: create)
      --scheduler MODE    Scheduler mode: normal | lambda (default: normal)
      --kubernetes-version VERSION    Kubernetes version to stamp/build/use (default: v1.33.1)
  -i, --identity-file     SSH identity file for EC2 access
  -h, --help              Show help
EOF
}

N_WORKERS=2
BEHAVIOR="${BEHAVIOR:-CREATE}"
SCHEDULER_MODE="${SCHEDULER_MODE:-normal}"
KUBERNETES_VERSION_VALUE="${KUBERNETES_VERSION:-v1.33.1}"
IDENTITY_FILE_ARG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -w|--workers)        N_WORKERS="$2"; shift 2 ;;
    -b|--behavior)       BEHAVIOR="${2^^}"; shift 2 ;;
    --scheduler)         SCHEDULER_MODE="$2"; shift 2 ;;
    --kubernetes-version) KUBERNETES_VERSION_VALUE="$2"; shift 2 ;;
    -i|--identity-file)  IDENTITY_FILE_ARG="$2"; shift 2 ;;
    -h|--help)           usage; exit 0 ;;
    *)
      echo "Unknown arg: $1"
      usage
      exit 1
      ;;
  esac
done

case "${BEHAVIOR}" in
  CREATE|REPLACE) ;;
  *)
    echo "Invalid behavior: ${BEHAVIOR}. Use create or replace."
    exit 1
    ;;
esac

case "${SCHEDULER_MODE}" in
  normal|lambda) ;;
  *)
    echo "Invalid scheduler mode: ${SCHEDULER_MODE}. Use normal or lambda."
    exit 1
    ;;
esac

if ! [[ "${KUBERNETES_VERSION_VALUE}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-.+][0-9A-Za-z.-]+)?$ ]]; then
  echo "Invalid Kubernetes version: ${KUBERNETES_VERSION_VALUE}"
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_LOCAL_DIR="${REPO_LOCAL_DIR:-$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel 2>/dev/null || (cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd))}"
[[ -d "${REPO_LOCAL_DIR}" ]] || { echo "Repo root not found: ${REPO_LOCAL_DIR}"; exit 1; }

K8S_DIR="${K8S_DIR:-${REPO_LOCAL_DIR}/kubernetes}"
[[ -d "${K8S_DIR}" ]] || { echo "Missing expected directory: ${K8S_DIR}"; exit 1; }
[[ -f "${K8S_DIR}/Makefile" ]] || { echo "Does not look like a Kubernetes source tree: ${K8S_DIR}"; exit 1; }

OUT_DIR="${OUT_DIR:-${REPO_LOCAL_DIR}/_ec2_out}"

export N_WORKERS
export BEHAVIOR
export SCHEDULER_MODE
export AWS_REGION="${AWS_REGION:-us-east-1}"
export IDENTITY_FILE="${IDENTITY_FILE_ARG:-${IDENTITY_FILE:-$HOME/.ssh/2025_06_03.pem}}"
export GO_VERSION="${GO_VERSION:-1.24.6}"
export TAG_PREFIX="${TAG_PREFIX:-ctrlless}"
export K8S_CLUSTER_NAME="${K8S_CLUSTER_NAME:-${TAG_PREFIX}}"
export LAMBDA_RESOURCE_PREFIX="${LAMBDA_RESOURCE_PREFIX:-${TAG_PREFIX}-lambda}"
export LAMBDA_KUBECONFIG_PARAMETER_PREFIX="${LAMBDA_KUBECONFIG_PARAMETER_PREFIX:-/${LAMBDA_RESOURCE_PREFIX}/admin-private-kubeconfig}"
export KUBERNETES_VERSION="${KUBERNETES_VERSION_VALUE}"
export PODGC_CONTROLLER_NAME="${PODGC_CONTROLLER_NAME:-pod-garbage-collector-controller}"
export JOB_CONTROLLER_NAME="${JOB_CONTROLLER_NAME:-job-controller}"
export TTL_AFTER_FINISHED_CONTROLLER_NAME="${TTL_AFTER_FINISHED_CONTROLLER_NAME:-ttl-after-finished-controller}"
export NAMESPACE_CONTROLLER_NAME="${NAMESPACE_CONTROLLER_NAME:-namespace-controller}"
export POD_CIDR="${POD_CIDR:-10.244.0.0/16}"
export SERVICE_CIDR="${SERVICE_CIDR:-10.96.0.0/12}"
export CNI_MANIFEST_URL="${CNI_MANIFEST_URL:-https://raw.githubusercontent.com/flannel-io/flannel/master/Documentation/kube-flannel.yml}"
export CNI_PLUGINS_VERSION="${CNI_PLUGINS_VERSION:-v1.5.1}"
export REPO_LOCAL_DIR
export K8S_DIR
export OUT_DIR

mkdir -p "${OUT_DIR}"
chmod +x "${SCRIPT_DIR}/aws_setup.sh" "${SCRIPT_DIR}/nodes_setup.sh"

echo "== setup_ec2 =="
echo "Workers:            ${N_WORKERS}"
echo "Behavior:           ${BEHAVIOR}"
echo "Scheduler mode:     ${SCHEDULER_MODE}"
echo "Kubernetes version: ${KUBERNETES_VERSION}"
echo "Region:             ${AWS_REGION}"
echo "Identity:           ${IDENTITY_FILE}"
echo "Repo:               ${REPO_LOCAL_DIR}"
echo "Kubernetes tree:    ${K8S_DIR}"
echo "Cluster tag prefix: ${TAG_PREFIX}"
echo "Cluster name:       ${K8S_CLUSTER_NAME}"
echo "Out dir:            ${OUT_DIR}"
echo

"${SCRIPT_DIR}/aws_setup.sh" -w "${N_WORKERS}" -b "${BEHAVIOR}"
"${SCRIPT_DIR}/nodes_setup.sh"

echo
echo "EC2 Kubernetes cluster is ready."
echo "  cluster env:       ${OUT_DIR}/cluster.env"
echo "  private kubeconfig ${OUT_DIR}/admin.private.conf"
echo "  public kubeconfig: ${OUT_DIR}/admin.public.conf"
