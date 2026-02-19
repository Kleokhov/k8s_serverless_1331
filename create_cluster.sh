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
    --no-build)       DO_BUILD=0; shift ;;
    --kube-version)   KUBE_VERSION_BASE="$2"; shift 2 ;;
    -h|--help)        usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 2 ;;
  esac
done

ARCH="$(uname -m)"
case "$ARCH" in
  aarch64|arm64) ARCH="arm64" ;;
  x86_64|amd64)  ARCH="amd64" ;;
  *) echo "Unsupported arch: $(uname -m)"; exit 1 ;;
esac

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

WORK_BAK="$(mktemp)"
WORKSUM_BAK="$(mktemp)"
RESTORE_WORK=0

# Track whether vendor changed, so we can revert it if requested.
VENDOR_DIR="$K8S_DIR/vendor"
VENDOR_WAS_DIRTY=0

cleanup() {
  if [[ "$RESTORE_WORK" -eq 1 ]]; then
    echo "==> Restoring original go.work"
    cp "$WORK_BAK" "$K8S_DIR/go.work"
    if [[ -s "$WORKSUM_BAK" ]]; then
      cp "$WORKSUM_BAK" "$K8S_DIR/go.work.sum"
    else
      rm -f "$K8S_DIR/go.work.sum" || true
    fi
  fi

  rm -f "$WORK_BAK" "$WORKSUM_BAK" || true
}
trap cleanup EXIT

# --- Mirror apiserver into kubernetes/_local/apiserver -----------------------
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

# --- Patch go.work to use ./_local/apiserver --------------------------------
echo "==> Temporarily patching go.work to use ./$OVERLAY_REL"
cp "$K8S_DIR/go.work" "$WORK_BAK"
RESTORE_WORK=1
if [[ -f "$K8S_DIR/go.work.sum" ]]; then
  cp "$K8S_DIR/go.work.sum" "$WORKSUM_BAK"
else
  : > "$WORKSUM_BAK"
fi

if grep -qE '^\s*\.\./apiserver\s*$' go.work; then
  go work edit -dropuse=../apiserver
fi
if ! grep -qE "^\s*\./${OVERLAY_REL}\s*$" go.work; then
  go work edit -use="./${OVERLAY_REL}"
fi
go work sync

# --- Version stamp -----------------------------------------------------------
KUBE_GIT_COMMIT="$(git -C "$K8S_DIR" rev-parse --short HEAD 2>/dev/null || echo 'local')"
export KUBE_GIT_COMMIT
export KUBE_GIT_TREE_STATE=clean
export KUBE_GIT_VERSION="${KUBE_VERSION_BASE}-${KUBE_GIT_COMMIT}"
echo "==> Using version stamp: KUBE_GIT_VERSION=$KUBE_GIT_VERSION"

# --- Workspace + vendor ---------------------------
# In workspace mode, -mod can only be readonly or vendor.
export GOFLAGS="-buildvcs=false -mod=vendor"
echo "==> Using GOFLAGS=$GOFLAGS"

echo "==> Running 'go work vendor' to sync vendor/ for workspace"
# Mark dirty before/after so we can revert if desired
if git -C "$K8S_DIR" diff --quiet -- vendor/ 2>/dev/null; then
  : # clean
else
  VENDOR_WAS_DIRTY=1
fi
go work vendor
if ! git -C "$K8S_DIR" diff --quiet -- vendor/ 2>/dev/null; then
  VENDOR_WAS_DIRTY=1
fi

# --- Build Kubernetes tarball ------------------------------------------------
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

# --- Build kind node image from the tarball ---------------------------------
echo "==> Building kind node image from tarball: $KIND_IMAGE"
kind build node-image \
  --type file "$TARBALL" \
  --image "$KIND_IMAGE"

# --- Create cluster ----------------------------------------------------------
echo "==> Recreating kind cluster: $CLUSTER_NAME"
kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true

KIND_CFG="$(mktemp)"
{
  echo "kind: Cluster"
  echo "apiVersion: kind.x-k8s.io/v1alpha4"

  # Patch kubeadm's ClusterConfiguration that kind uses during kubeadm init
  echo "kubeadmConfigPatches:"
  echo "- |"
  echo "  apiVersion: kubeadm.k8s.io/v1beta3"
  echo "  kind: ClusterConfiguration"
  echo "  apiServer:"
  echo "    extraArgs:"
  echo "      authorization-mode: \"Node,RBAC\""
  echo "      anonymous-auth: \"true\""

  echo "nodes:"
  echo "- role: control-plane"
  for ((i=0; i<WORKERS; i++)); do
    echo "- role: worker"
  done
} > "$KIND_CFG"

kind create cluster \
  --name "$CLUSTER_NAME" \
  --image "$KIND_IMAGE" \
  --config "$KIND_CFG" \
  --retain
