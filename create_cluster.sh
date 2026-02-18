#!/usr/bin/env bash
set -euo pipefail

# Spawn a kind cluster whose control-plane uses your locally customized Kubernetes build,
# where the custom apiserver is wired in via go.work (../apiserver).
#
# Assumptions:
# - Repo layout:
#     <TOPDIR>/
#       kubernetes/    (your k8s checkout)
#       apiserver/            (your local apiserver module; referenced as ../apiserver)
# - kubernetes-1.33.1/go.work contains "../apiserver" (you already did `go work edit -use=../apiserver; go work sync`)
#
# Usage:
#   ./spawn-kind-custom.sh                # build + create cluster
#   ./spawn-kind-custom.sh --no-build     # only (re)create cluster from existing image
#   ./spawn-kind-custom.sh --build        # force rebuild
#   ./spawn-kind-custom.sh --name foo     # cluster name
#   ./spawn-kind-custom.sh --image tag    # kind node image tag
#   ./spawn-kind-custom.sh --workers 2    # add workers
#
# Notes:
# - This builds a kind node image from the Kubernetes server release tarball produced by `make quick-release`,
#   then creates a kind cluster from that node image.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
TOPDIR="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"

K8S_DIR_DEFAULT="$TOPDIR/kubernetes"
APISERVER_DIR_DEFAULT="$TOPDIR/apiserver"

K8S_DIR="$K8S_DIR_DEFAULT"
APISERVER_DIR="$APISERVER_DIR_DEFAULT"

CLUSTER_NAME="local-apiserver"
KIND_IMAGE="kindest-local:dev"
WORKERS=0

DO_BUILD=1

usage() {
  cat <<EOF
Usage: $0 [options]
  --k8s-dir PATH        Path to kubernetes repo (default: $K8S_DIR_DEFAULT)
  --apiserver-dir PATH  Path to local apiserver module (default: $APISERVER_DIR_DEFAULT)
  --name NAME           Kind cluster name (default: $CLUSTER_NAME)
  --image IMAGE         Kind node image tag (default: $KIND_IMAGE)
  --workers N           Number of worker nodes (default: $WORKERS)
  --build               Force build (default)
  --no-build            Skip build, only recreate cluster using existing kind image
  -h|--help             Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --k8s-dir)        K8S_DIR="$2"; shift 2 ;;
    --apiserver-dir)  APISERVER_DIR="$2"; shift 2 ;;
    --name)           CLUSTER_NAME="$2"; shift 2 ;;
    --image)          KIND_IMAGE="$2"; shift 2 ;;
    --workers)        WORKERS="$2"; shift 2 ;;
    --build)          DO_BUILD=1; shift ;;
    --no-build)       DO_BUILD=0; shift ;;
    -h|--help)        usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 2 ;;
  esac
done

# ----------- arch mapping ----------------------------------------------------
ARCH="$(uname -m)"
case "$ARCH" in
  aarch64|arm64) ARCH="arm64" ;;
  x86_64|amd64)  ARCH="amd64" ;;
  *) echo "Unsupported arch: $(uname -m)"; exit 1 ;;
esac

# ----------- basic sanity ----------------------------------------------------
if [[ ! -d "$K8S_DIR" ]]; then
  echo "K8S_DIR not found: $K8S_DIR"
  exit 1
fi

if [[ ! -d "$APISERVER_DIR" ]]; then
  echo "APISERVER_DIR not found: $APISERVER_DIR"
  exit 1
fi

# ----------- Ensure the submodule has a real .git dir (if applicable) -------
if [[ -f "$K8S_DIR/.git" && ! -d "$K8S_DIR/.git" ]]; then
  echo "Converting submodule gitfile → real .git/ directory"
  git -C "$TOPDIR" submodule absorbgitdirs "$(basename "$K8S_DIR")"
fi

cd "$K8S_DIR"

# ----------- Verify go.work includes ../apiserver ----------------------------
if [[ ! -f go.work ]]; then
  echo "go.work not found in $K8S_DIR"
  echo "If you rely on workspaces, create it and add ../apiserver."
  exit 1
fi

if ! grep -qE '^\s*\.\./apiserver\s*$' go.work; then
  echo "go.work does not include ../apiserver."
  echo "Run these in $K8S_DIR:"
  echo "  go work edit -use=../apiserver"
  echo "  go work sync"
  exit 1
fi

# ----------- WSL networking workaround ---------------------------------------
if grep -qi microsoft /proc/version 2>/dev/null; then
  export KUBE_RSYNC_PORT=39999
  export KUBE_BUILD_NO_HOSTNETWORK=1
fi

# ----------- Build Kubernetes (with your workspace-wired apiserver) ----------
if [[ "$DO_BUILD" -eq 1 ]]; then
  echo "==> Building Kubernetes quick-release (ARCH=$ARCH) using go.work (../apiserver)"

  # Make version stamping resilient even if .git metadata is odd in some setups.
  export KUBE_GIT_COMMIT="$(git -C "$K8S_DIR" rev-parse --short HEAD 2>/dev/null || echo 'local')"
  export KUBE_GIT_TREE_STATE=clean
  export KUBE_GIT_VERSION="v1.33.1-${KUBE_GIT_COMMIT}"

  # Optional: add debug flags if you want:
  # export KUBE_GCFLAGS='all=-N -l -m'

  # Produces: _output/release-tars/kubernetes-server-linux-$ARCH.tar.gz
  make quick-release
else
  echo "==> Skipping build (--no-build)"
fi

TARBALL="$K8S_DIR/_output/release-tars/kubernetes-server-linux-$ARCH.tar.gz"
if [[ ! -f "$TARBALL" ]]; then
  echo "Server tarball not found: $TARBALL"
  echo "Run with --build (or ensure make quick-release succeeded)."
  exit 1
fi

# ----------- Build kind node image from the tarball --------------------------
echo "==> Building kind node image: $KIND_IMAGE"
kind build node-image \
  --type file "$TARBALL" \
  --image "$KIND_IMAGE"

# ----------- Create kind cluster from that node image ------------------------
echo "==> Recreating kind cluster: $CLUSTER_NAME"
kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true

# Create a tiny config on the fly (add workers if requested).
KIND_CFG="$(mktemp)"
trap 'rm -f "$KIND_CFG"' EXIT

{
  echo "kind: Cluster"
  echo "apiVersion: kind.x-k8s.io/v1alpha4"
  echo "nodes:"
  echo "- role: control-plane"
  for ((i=0; i<WORKERS; i++)); do
    echo "- role: worker"
  done
} > "$KIND_CFG"

kind create cluster \
  --name "$CLUSTER_NAME" \
  --image "$KIND_IMAGE" \
  --config "$KIND_CFG"

# ----------- Verify we’re running and show apiserver image -------------------
echo "==> Cluster is up. Context: kind-$CLUSTER_NAME"
kubectl cluster-info --context "kind-$CLUSTER_NAME"

echo "==> kube-apiserver pod + image:"
kubectl --context "kind-$CLUSTER_NAME" -n kube-system \
  get pod -l component=kube-apiserver -o wide

kubectl --context "kind-$CLUSTER_NAME" -n kube-system \
  get pod -l component=kube-apiserver \
  -o jsonpath='{.items[0].spec.containers[0].image}{"\n"}'

echo "==> Done."
