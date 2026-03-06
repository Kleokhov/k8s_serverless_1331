#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
TOPDIR="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || echo "$SCRIPT_DIR")"

K8S_DIR="${K8S_DIR:-$TOPDIR/kubernetes}"
APISERVER_DIR="${APISERVER_DIR:-$TOPDIR/apiserver}"

CLUSTER_NAME="${CLUSTER_NAME:-local-apiserver}"
KIND_IMAGE="${KIND_IMAGE:-kindest-local:dev}"
WORKERS="${WORKERS:-0}"

DO_BUILD=1
KUBE_VERSION_BASE="${KUBE_VERSION_BASE:-v1.33.1}"

STORAGE_BACKEND="${STORAGE_BACKEND:-etcd}"
DYNAMO_REGION="${DYNAMO_REGION:-us-east-1}"
DYNAMO_TABLE="${DYNAMO_TABLE:-dynamo}"
DYNAMO_ENDPOINT="${DYNAMO_ENDPOINT:-http://dynamodb-local:8000}"
DYNAMO_CONTAINER_NAME="${DYNAMO_CONTAINER_NAME:-dynamodb-local}"
START_DYNAMO="${START_DYNAMO:-1}"

usage() {
  cat <<EOF
Usage: $0 [options]
  --k8s-dir PATH        Path to kubernetes repo (default: $K8S_DIR)
  --apiserver-dir PATH  Path to apiserver module root (default: $APISERVER_DIR)
  --name NAME           Kind cluster name (default: $CLUSTER_NAME)
  --image IMAGE         kind node image tag (default: $KIND_IMAGE)
  --workers N           Number of worker nodes (default: $WORKERS)
  --no-build            Skip building; only recreate cluster using existing image
  --kube-version V      Base semver for stamping (default: $KUBE_VERSION_BASE)
  --storage-backend B   Storage backend: etcd|dynamo (default: $STORAGE_BACKEND)
  --dynamo-region R     DynamoDB region (default: $DYNAMO_REGION)
  --dynamo-table T      DynamoDB table/base table (default: $DYNAMO_TABLE)
  --dynamo-endpoint U   DynamoDB endpoint reachable from kind node (default: $DYNAMO_ENDPOINT)
  --no-start-dynamo     Do not start local dynamodb-local container automatically
  -h|--help             Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --k8s-dir)          K8S_DIR="$2"; shift 2 ;;
    --apiserver-dir)    APISERVER_DIR="$2"; shift 2 ;;
    --name)             CLUSTER_NAME="$2"; shift 2 ;;
    --image)            KIND_IMAGE="$2"; shift 2 ;;
    --workers)          WORKERS="$2"; shift 2 ;;
    --no-build)         DO_BUILD=0; shift ;;
    --kube-version)     KUBE_VERSION_BASE="$2"; shift 2 ;;
    --storage-backend)  STORAGE_BACKEND="$2"; shift 2 ;;
    --dynamo-region)    DYNAMO_REGION="$2"; shift 2 ;;
    --dynamo-table)     DYNAMO_TABLE="$2"; shift 2 ;;
    --dynamo-endpoint)  DYNAMO_ENDPOINT="$2"; shift 2 ;;
    --no-start-dynamo)  START_DYNAMO=0; shift ;;
    -h|--help)          usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 2 ;;
  esac
done

ARCH="$(uname -m)"
case "$ARCH" in
  aarch64|arm64) ARCH="arm64" ;;
  x86_64|amd64)  ARCH="amd64" ;;
  *) echo "Unsupported arch: $(uname -m)"; exit 1 ;;
esac

# For WSL
if [[ -f "$K8S_DIR/.git" && ! -d "$K8S_DIR/.git" ]]; then
  echo "Converting submodule gitfile → real .git/ directory"
  git -C "$TOPDIR" submodule absorbgitdirs "$(basename "$K8S_DIR")"
fi

if grep -qi microsoft /proc/version 2>/dev/null; then
  export KUBE_RSYNC_PORT=39999
  export KUBE_BUILD_NO_HOSTNETWORK=1
fi

cd "$K8S_DIR"
[[ -f go.work ]] || { echo "ERROR: $K8S_DIR/go.work not found"; exit 1; }

# Copying local apiserver into kubernetes/_local/apiserver
OVERLAY_REL="_local/apiserver"
OVERLAY_DIR="$K8S_DIR/$OVERLAY_REL"

echo "==> Mirroring apiserver into kubernetes/$OVERLAY_REL"
mkdir -p "$OVERLAY_DIR"
rsync -a --delete \
  --exclude '.git/' \
  --exclude 'bin/' \
  --exclude '_output/' \
  --exclude '.DS_Store' \
  "$APISERVER_DIR/" "$OVERLAY_DIR/"

# Ignore overlay in git
if [[ -d "$K8S_DIR/.git" ]]; then
  mkdir -p "$K8S_DIR/.git/info"
  if ! grep -qE "^_local/" "$K8S_DIR/.git/info/exclude" 2>/dev/null; then
    echo "_local/" >> "$K8S_DIR/.git/info/exclude" || true
  fi
fi

# Point go.work at ./_local/apiserver (Permanent)
echo "==> Ensuring go.work uses ./$OVERLAY_REL"
if grep -qE '^\s*\.\./apiserver\s*$' go.work; then
  go work edit -dropuse=../apiserver
fi
if ! grep -qE "^\s*\./${OVERLAY_REL}\s*$" go.work; then
  go work edit -use="./${OVERLAY_REL}"
fi
go work sync

KUBE_GIT_COMMIT="$(git -C "$K8S_DIR" rev-parse --short HEAD 2>/dev/null || echo 'local')"
export KUBE_GIT_COMMIT
export KUBE_GIT_TREE_STATE=clean
export KUBE_GIT_VERSION="${KUBE_VERSION_BASE}-${KUBE_GIT_COMMIT}"
echo "==> Using version stamp: KUBE_GIT_VERSION=$KUBE_GIT_VERSION"

export GOFLAGS="-buildvcs=false -mod=vendor"
echo "==> Using GOFLAGS=$GOFLAGS"

echo "==> Running 'go work vendor' to sync vendor/ for workspace"
go work vendor

if [[ "$DO_BUILD" -eq 1 ]]; then
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

echo "==> Building kind node image from tarball: $KIND_IMAGE"
kind build node-image \
  --type file "$TARBALL" \
  --image "$KIND_IMAGE"

if [[ "$STORAGE_BACKEND" == "dynamo" && "$START_DYNAMO" -eq 1 ]]; then
  echo "==> Ensuring local DynamoDB container is running"
  docker rm -f "$DYNAMO_CONTAINER_NAME" >/dev/null 2>&1 || true
  docker network inspect kind >/dev/null 2>&1 || docker network create kind
  docker run -d \
    --name "$DYNAMO_CONTAINER_NAME" \
    --network kind \
    amazon/dynamodb-local \
    -jar DynamoDBLocal.jar -inMemory -sharedDb >/dev/null
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
  echo "  kubeadmConfigPatches:"
  echo "  - |"
  echo "    apiVersion: kubeadm.k8s.io/v1beta3"
  echo "    kind: ClusterConfiguration"
  echo "    apiServer:"
  echo "      extraArgs:"
  echo "        authorization-mode: \"Node,RBAC\""
  echo "        anonymous-auth: \"true\""
  echo "        storage-backend: \"$STORAGE_BACKEND\""

  if [[ "$STORAGE_BACKEND" == "dynamo" ]]; then
    echo "        dynamo-region: \"$DYNAMO_REGION\""
    echo "        dynamo-table: \"$DYNAMO_TABLE\""
    echo "        dynamo-endpoint: \"$DYNAMO_ENDPOINT\""
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
