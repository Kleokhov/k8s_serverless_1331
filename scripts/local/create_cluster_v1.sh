#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd)"
K8S_DIR="$ROOT_DIR/kubernetes"

CLUSTER_NAME="${CLUSTER_NAME:-kind}"
KIND_IMAGE="${KIND_IMAGE:-kindest-local:dev}"
WORKERS="${WORKERS:-0}"

SCHEDULER_MODE="${SCHEDULER_MODE:-normal}" # normal | lambda
PODGC_CONTROLLER_NAME="${PODGC_CONTROLLER_NAME:-pod-garbage-collector-controller}"
JOB_CONTROLLER_NAME="${JOB_CONTROLLER_NAME:-job-controller}"
TTL_AFTER_FINISHED_CONTROLLER_NAME="${TTL_AFTER_FINISHED_CONTROLLER_NAME:-ttl-after-finished-controller}"
NAMESPACE_CONTROLLER_NAME="${NAMESPACE_CONTROLLER_NAME:-namespace-controller}"
LAMBDA_BASE_CONTROLLERS="${LAMBDA_BASE_CONTROLLERS:-*,bootstrapsigner,tokencleaner}"
LAMBDA_DISABLED_CONTROLLERS="${LAMBDA_BASE_CONTROLLERS},-${PODGC_CONTROLLER_NAME},-${JOB_CONTROLLER_NAME},-${TTL_AFTER_FINISHED_CONTROLLER_NAME},-${NAMESPACE_CONTROLLER_NAME}"

usage() {
  cat <<'EOF'
Usage: ./scripts/create_cluster.sh [options]

Options:
  --name NAME        Kind cluster name (default: kind)
  --image IMAGE      Kind node image tag (default: kindest-local:dev)
  --workers N        Number of worker nodes (default: 0)
  --scheduler MODE   Scheduler mode: normal | lambda (default: normal)
  -h, --help         Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)        CLUSTER_NAME="$2"; shift 2 ;;
    --image)       KIND_IMAGE="$2"; shift 2 ;;
    --workers)     WORKERS="$2"; shift 2 ;;
    --scheduler)   SCHEDULER_MODE="$2"; shift 2 ;;
    -h|--help)     usage; exit 0 ;;
    *) echo "Unknown argument: $1"; usage; exit 2 ;;
  esac
done

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: required command not found: $1"
    exit 1
  }
}

seed_kube_version_vars() {
  [[ -n "${KUBE_GIT_VERSION:-}" ]] && return 0
  [[ -e "$K8S_DIR/.git" ]] && return 0

  local cross_version
  local derived_version
  cross_version="$(<"$K8S_DIR/build/build-image/cross/VERSION")"

  if [[ "$cross_version" =~ ^(v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?)(-go[0-9].*)?$ ]]; then
    derived_version="${BASH_REMATCH[1]}"
    export KUBE_GIT_VERSION="$derived_version"
    export KUBE_GIT_TREE_STATE="${KUBE_GIT_TREE_STATE:-archive}"

    if [[ "$derived_version" =~ ^v([0-9]+)\.([0-9]+) ]]; then
      export KUBE_GIT_MAJOR="${KUBE_GIT_MAJOR:-${BASH_REMATCH[1]}}"
      export KUBE_GIT_MINOR="${KUBE_GIT_MINOR:-${BASH_REMATCH[2]}}"
    fi

    echo "==> Using archive Kubernetes version metadata: $KUBE_GIT_VERSION"
    return 0
  fi

  echo "ERROR: unable to derive KUBE_GIT_VERSION from $K8S_DIR/build/build-image/cross/VERSION"
  exit 1
}

disable_kind_scheduler() {
  local control_plane_node
  local attempt

  control_plane_node="$(
    kind get nodes --name "$CLUSTER_NAME" | awk '/control-plane/ { print; exit }'
  )"

  [[ -n "$control_plane_node" ]] || {
    echo "ERROR: unable to locate kind control-plane node for cluster: $CLUSTER_NAME"
    exit 1
  }

  echo "==> Disabling kube-scheduler static pod on: $control_plane_node"
  docker exec "$control_plane_node" rm -f /etc/kubernetes/manifests/kube-scheduler.yaml

  for attempt in {1..30}; do
    if ! docker exec "$control_plane_node" sh -c '
      test -f /etc/kubernetes/manifests/kube-scheduler.yaml && exit 0
      if command -v crictl >/dev/null 2>&1; then
        crictl ps --name kube-scheduler -q | grep -q .
        exit $?
      fi
      pgrep -f "[k]ube-scheduler" >/dev/null 2>&1
    '; then
      echo "==> kube-scheduler disabled"
      return 0
    fi

    sleep 1
  done

  echo "ERROR: kube-scheduler is still running after disabling the static pod manifest"
  exit 1
}

require_cmd docker
require_cmd kind
require_cmd make
require_cmd go

docker info >/dev/null 2>&1 || {
  echo "ERROR: Docker daemon is not running"
  exit 1
}

[[ -d "$K8S_DIR" ]] || {
  echo "ERROR: expected Kubernetes repo at: $K8S_DIR"
  exit 1
}

[[ -f "$K8S_DIR/Makefile" ]] || {
  echo "ERROR: $K8S_DIR does not look like a Kubernetes repo"
  exit 1
}

case "$SCHEDULER_MODE" in
  normal|lambda) ;;
  *)
    echo "ERROR: --scheduler must be 'normal' or 'lambda'"
    exit 1
    ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
  aarch64|arm64) ARCH="arm64" ;;
  x86_64|amd64)  ARCH="amd64" ;;
  *)
    echo "ERROR: unsupported architecture: $(uname -m)"
    exit 1
    ;;
esac

if grep -qiE '(microsoft|wsl)' /proc/version /proc/sys/kernel/osrelease 2>/dev/null; then
  export KUBE_RSYNC_PORT="${KUBE_RSYNC_PORT:-39999}"
fi

cd "$K8S_DIR"

echo "==> Building Kubernetes release tarball for linux/$ARCH"
export KUBE_BUILD_PLATFORMS="linux/$ARCH"
seed_kube_version_vars
make quick-release

TARBALL="$K8S_DIR/_output/release-tars/kubernetes-server-linux-$ARCH.tar.gz"
[[ -f "$TARBALL" ]] || {
  echo "ERROR: server tarball not found: $TARBALL"
  exit 1
}

echo "==> Building kind node image: $KIND_IMAGE"
kind build node-image \
  --type file "$TARBALL" \
  --image "$KIND_IMAGE"

KIND_CFG="$(mktemp)"

cleanup() {
  rm -f "$KIND_CFG"
}
trap cleanup EXIT

{
  cat <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
EOF

  if [[ "$SCHEDULER_MODE" == "lambda" ]]; then
    cat <<EOF
  kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta4
    kind: ClusterConfiguration
    controllerManager:
      extraArgs:
        controllers: "${LAMBDA_DISABLED_CONTROLLERS}"
EOF
  fi

  for ((i=0; i<WORKERS; i++)); do
    cat <<'EOF'
- role: worker
EOF
  done
} > "$KIND_CFG"

echo "==> Recreating kind cluster: $CLUSTER_NAME"
kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true

kind create cluster \
  --name "$CLUSTER_NAME" \
  --image "$KIND_IMAGE" \
  --config "$KIND_CFG"

if [[ "$SCHEDULER_MODE" == "lambda" ]]; then
  disable_kind_scheduler
fi

echo "==> Cluster created: $CLUSTER_NAME"
echo "==> Scheduler mode: $SCHEDULER_MODE"

if [[ "$SCHEDULER_MODE" == "normal" ]]; then
  echo "==> Running with default kube-scheduler and default kube-controller-manager controllers"
else
  echo "==> kube-scheduler disabled by removing the control-plane static pod manifest"
  echo "==> kube-controller-manager disabled controllers: ${LAMBDA_DISABLED_CONTROLLERS}"
fi
