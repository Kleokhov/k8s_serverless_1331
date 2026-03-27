#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
TOPDIR="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || echo "$SCRIPT_DIR")"

AWS_DIR="${AWS_DIR:-$HOME/.aws}"
K8S_DIR="${K8S_DIR:-$TOPDIR/kubernetes}"

CLUSTER_NAME="${CLUSTER_NAME:-kind}"
KIND_IMAGE="${KIND_IMAGE:-kindest-local:dev}"
WORKERS="${WORKERS:-0}"

DO_BUILD=1
KUBE_VERSION_BASE="${KUBE_VERSION_BASE:-v1.33.1}"

# Storage modes:
#   etcd          -> kube-apiserver --storage-backend=etcd3
#   dynamo-local  -> kube-apiserver --storage-backend=dynamo + --dynamo-endpoint=...
#   dynamo-aws    -> kube-apiserver --storage-backend=dynamo (no endpoint)
STORAGE_BACKEND="${STORAGE_BACKEND:-etcd}"
DYNAMO_REGION="${DYNAMO_REGION:-us-east-1}"
DYNAMO_TABLE="${DYNAMO_TABLE:-dynamo}"
DYNAMO_ENDPOINT="${DYNAMO_ENDPOINT:-http://dynamodb-local:8000}"
DYNAMO_CONTAINER_NAME="${DYNAMO_CONTAINER_NAME:-dynamodb-local}"
PRECREATE_DYNAMO_TABLES_SCRIPT="${PRECREATE_DYNAMO_TABLES_SCRIPT:-$TOPDIR/precreate_dynamo_tables.sh}"

usage() {
  cat <<EOF
Usage: $0 [options]
  --k8s-dir PATH        Path to kubernetes repo (default: $K8S_DIR)
  --name NAME           Kind cluster name (default: $CLUSTER_NAME)
  --image IMAGE         Kind node image tag (default: $KIND_IMAGE)
  --workers N           Number of worker nodes (default: $WORKERS)
  --no-build            Skip building; only recreate cluster using existing image
  --kube-version V      Base semver for stamping (default: $KUBE_VERSION_BASE)
  --storage-backend B   Storage mode: etcd|dynamo-local|dynamo-aws (default: $STORAGE_BACKEND)
  --dynamo-region R     DynamoDB region (default: $DYNAMO_REGION)
  --dynamo-table T      DynamoDB table/base table (default: $DYNAMO_TABLE)
  --dynamo-endpoint U   DynamoDB endpoint for local mode (default: $DYNAMO_ENDPOINT)
  -h|--help             Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --k8s-dir)          K8S_DIR="$2"; shift 2 ;;
    --name)             CLUSTER_NAME="$2"; shift 2 ;;
    --image)            KIND_IMAGE="$2"; shift 2 ;;
    --workers)          WORKERS="$2"; shift 2 ;;
    --no-build)         DO_BUILD=0; shift ;;
    --kube-version)     KUBE_VERSION_BASE="$2"; shift 2 ;;
    --storage-backend)  STORAGE_BACKEND="$2"; shift 2 ;;
    --dynamo-region)    DYNAMO_REGION="$2"; shift 2 ;;
    --dynamo-table)     DYNAMO_TABLE="$2"; shift 2 ;;
    --dynamo-endpoint)  DYNAMO_ENDPOINT="$2"; shift 2 ;;
    -h|--help)          usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 2 ;;
  esac
done

APISERVER_STORAGE_BACKEND=""
USE_DYNAMO=0
USE_LOCAL_DYNAMO=0
USE_AWS_DYNAMO=0

case "$STORAGE_BACKEND" in
  etcd)
    APISERVER_STORAGE_BACKEND="etcd3"
    ;;
  dynamo-local)
    APISERVER_STORAGE_BACKEND="dynamo"
    USE_DYNAMO=1
    USE_LOCAL_DYNAMO=1
    ;;
  dynamo-aws)
    APISERVER_STORAGE_BACKEND="dynamo"
    USE_DYNAMO=1
    USE_AWS_DYNAMO=1
    ;;
  *)
    echo "ERROR: unsupported --storage-backend=$STORAGE_BACKEND (expected: etcd|dynamo-local|dynamo-aws)"
    exit 2
    ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
  aarch64|arm64) ARCH="arm64" ;;
  x86_64|amd64)  ARCH="amd64" ;;
  *) echo "Unsupported arch: $(uname -m)"; exit 1 ;;
esac

# Helpful when kubernetes is a submodule on WSL
if [[ -f "$K8S_DIR/.git" && ! -d "$K8S_DIR/.git" ]]; then
  echo "Converting submodule gitfile -> real .git/ directory"
  git -C "$TOPDIR" submodule absorbgitdirs "$(basename "$K8S_DIR")"
fi

if grep -qiE '(microsoft|wsl)' /proc/version /proc/sys/kernel/osrelease 2>/dev/null; then
  export KUBE_RSYNC_PORT="${KUBE_RSYNC_PORT:-39999}"
  export KUBE_BUILD_NO_HOSTNETWORK=1
fi

cd "$K8S_DIR"

[[ -f go.work ]] || {
  echo "ERROR: $K8S_DIR/go.work not found"
  exit 1
}

[[ -d "$K8S_DIR/staging/src/k8s.io/apiserver" ]] || {
  echo "ERROR: staged apiserver not found: $K8S_DIR/staging/src/k8s.io/apiserver"
  exit 1
}

# Fail fast if the old overlay is still referenced.
if grep -qE '^\s*\./_local/apiserver\s*$' go.work; then
  echo "ERROR: go.work still references ./_local/apiserver"
  echo "Remove it with: go work edit -dropuse=./_local/apiserver"
  exit 1
fi

# Ensure the staged apiserver module is present in the workspace.
if ! grep -qE '^\s*\./staging/src/k8s.io/apiserver\s*$' go.work; then
  echo "==> Adding ./staging/src/k8s.io/apiserver to go.work"
  go work edit -use=./staging/src/k8s.io/apiserver
fi

echo "==> Syncing go.work"
go work sync

KUBE_GIT_COMMIT="$(git -C "$K8S_DIR" rev-parse --short HEAD 2>/dev/null || echo 'local')"
export KUBE_GIT_COMMIT
export KUBE_GIT_TREE_STATE=clean
export KUBE_GIT_VERSION="${KUBE_VERSION_BASE}-${KUBE_GIT_COMMIT}"
echo "==> Using version stamp: KUBE_GIT_VERSION=$KUBE_GIT_VERSION"

export GOFLAGS="-buildvcs=false -mod=vendor"
echo "==> Using GOFLAGS=$GOFLAGS"

if [[ "$DO_BUILD" -eq 1 ]]; then
  echo "==> Refreshing vendor metadata"
  ./hack/update-vendor.sh

  echo "==> Building Kubernetes quick-release for linux/$ARCH"
  export KUBE_BUILD_PLATFORMS="linux/$ARCH"
  make quick-release
else
  echo "==> Skipping build (--no-build)"
fi

TARBALL="$K8S_DIR/_output/release-tars/kubernetes-server-linux-$ARCH.tar.gz"
if [[ ! -f "$TARBALL" ]]; then
  echo "ERROR: Server tarball not found: $TARBALL"
  exit 1
fi

echo "==> Building kind node image: $KIND_IMAGE"
kind build node-image \
  --type file "$TARBALL" \
  --image "$KIND_IMAGE"

if [[ "$USE_LOCAL_DYNAMO" -eq 1 ]]; then
  echo "==> Ensuring local DynamoDB container is running"
  docker rm -f "$DYNAMO_CONTAINER_NAME" >/dev/null 2>&1 || true
  docker network inspect kind >/dev/null 2>&1 || docker network create kind
  docker run -d \
    --name "$DYNAMO_CONTAINER_NAME" \
    --network kind \
    amazon/dynamodb-local \
    -jar DynamoDBLocal.jar -inMemory -sharedDb >/dev/null
fi

if [[ "$USE_AWS_DYNAMO" -eq 1 && ! -d "$AWS_DIR" ]]; then
  echo "ERROR: AWS shared config directory not found: $AWS_DIR"
  exit 1
fi

if [[ "$USE_AWS_DYNAMO" -eq 1 ]]; then
  [[ -x "$PRECREATE_DYNAMO_TABLES_SCRIPT" ]] || {
    echo "ERROR: precreate script not found or not executable: $PRECREATE_DYNAMO_TABLES_SCRIPT"
    exit 1
  }

  echo "==> Precreating DynamoDB tables for AWS backend"
  DYNAMO_REGION="$DYNAMO_REGION" \
  DYNAMO_TABLE="$DYNAMO_TABLE" \
  "$PRECREATE_DYNAMO_TABLES_SCRIPT"
fi

echo "==> Recreating kind cluster: $CLUSTER_NAME"
kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true

KIND_CFG="$(mktemp)"
trap 'rm -f "$KIND_CFG"' EXIT

{
  echo "kind: Cluster"
  echo "apiVersion: kind.x-k8s.io/v1alpha4"
  echo "nodes:"
  echo "- role: control-plane"

  if [[ "$USE_AWS_DYNAMO" -eq 1 ]]; then
    echo "  extraMounts:"
    echo "  - hostPath: \"$AWS_DIR\""
    echo "    containerPath: /root/.aws"
    echo "    readOnly: true"
  fi

  echo "  kubeadmConfigPatches:"
  echo "  - |"
  echo "    apiVersion: kubeadm.k8s.io/v1beta3"
  echo "    kind: ClusterConfiguration"
  echo "    apiServer:"
  echo "      extraArgs:"
  echo '        v: "4"'
  echo "        authorization-mode: \"Node,RBAC\""
  echo "        anonymous-auth: \"true\""
  echo "        storage-backend: \"$APISERVER_STORAGE_BACKEND\""

  if [[ "$USE_DYNAMO" -eq 1 ]]; then
    echo "        dynamo-region: \"$DYNAMO_REGION\""
    echo "        dynamo-table: \"$DYNAMO_TABLE\""
    if [[ "$USE_LOCAL_DYNAMO" -eq 1 ]]; then
      echo "        dynamo-endpoint: \"$DYNAMO_ENDPOINT\""
    fi
  fi

  if [[ "$USE_AWS_DYNAMO" -eq 1 ]]; then
    echo "      extraVolumes:"
    echo "      - name: aws-creds"
    echo "        hostPath: /root/.aws"
    echo "        mountPath: /root/.aws"
    echo "        readOnly: true"
    echo "        pathType: DirectoryOrCreate"
  fi

  for ((i=0; i<WORKERS; i++)); do
    echo "- role: worker"
  done
} > "$KIND_CFG"

kind create cluster \
  --name "$CLUSTER_NAME" \
  --image "$KIND_IMAGE" \
  --config "$KIND_CFG" \
  --retain