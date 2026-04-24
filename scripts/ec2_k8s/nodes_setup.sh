#!/usr/bin/env bash
set -euo pipefail

# Bootstraps a kubeadm-based EC2 Kubernetes cluster on the instances
# described by ${OUT_DIR}/cluster.env.

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing $1"; exit 1; }; }
need ssh
need scp
need tar
need awk
need sed
need make
need base64
need aws

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_LOCAL_DIR="${REPO_LOCAL_DIR:-$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel 2>/dev/null || (cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd))}"
OUT_DIR="${OUT_DIR:-${REPO_LOCAL_DIR}/_ec2_out}"

# shellcheck source=/dev/null
source "${OUT_DIR}/cluster.env"

K8S_DIR="${K8S_DIR:-${REPO_LOCAL_DIR}/kubernetes}"
GO_VERSION="${GO_VERSION:-1.24.6}"
SCHEDULER_MODE="${SCHEDULER_MODE:-normal}"
KUBERNETES_VERSION="${KUBERNETES_VERSION:-v1.33.1}"
PODGC_CONTROLLER_NAME="${PODGC_CONTROLLER_NAME:-pod-garbage-collector-controller}"
JOB_CONTROLLER_NAME="${JOB_CONTROLLER_NAME:-job-controller}"
TTL_AFTER_FINISHED_CONTROLLER_NAME="${TTL_AFTER_FINISHED_CONTROLLER_NAME:-ttl-after-finished-controller}"
NAMESPACE_CONTROLLER_NAME="${NAMESPACE_CONTROLLER_NAME:-namespace-controller}"
POD_CIDR="${POD_CIDR:-10.244.0.0/16}"
SERVICE_CIDR="${SERVICE_CIDR:-10.96.0.0/12}"
CNI_MANIFEST_URL="${CNI_MANIFEST_URL:-https://raw.githubusercontent.com/flannel-io/flannel/master/Documentation/kube-flannel.yml}"
CNI_PLUGINS_VERSION="${CNI_PLUGINS_VERSION:-v1.5.1}"
K8S_CLUSTER_NAME="${K8S_CLUSTER_NAME:-${TAG_PREFIX}}"
LAMBDA_RESOURCE_PREFIX="${LAMBDA_RESOURCE_PREFIX:-${TAG_PREFIX}-lambda}"
LAMBDA_KUBECONFIG_PARAMETER_PREFIX="${LAMBDA_KUBECONFIG_PARAMETER_PREFIX:-/${LAMBDA_RESOURCE_PREFIX}/admin-private-kubeconfig}"

case "${SCHEDULER_MODE}" in
  normal|lambda) ;;
  *)
    echo "Invalid SCHEDULER_MODE=${SCHEDULER_MODE}. Use normal or lambda."
    exit 1
    ;;
esac

ETCD_VERSION="${ETCD_VERSION:-v3.5.15}"

SOCK_DIR="${SOCK_DIR:-${REPO_LOCAL_DIR}/_ssh_mux}"
mkdir -p "${SOCK_DIR}"
SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o IdentitiesOnly=yes
  -o PreferredAuthentications=publickey
  -i "${IDENTITY_FILE}"
  -o ControlMaster=auto
  -o ControlPath="${SOCK_DIR}/%r@%h:%p"
  -o ControlPersist=600
)

ssh_do(){ local host="$1"; shift; ssh "${SSH_OPTS[@]}" "ubuntu@${host}" "$@"; }
scp_to(){ local host="$1"; shift; scp "${SSH_OPTS[@]}" "$@" "ubuntu@${host}:/home/ubuntu/"; }
prime_conn(){ ssh -fN "${SSH_OPTS[@]}" "ubuntu@$1" || true; }
refresh_kubeconfigs() {
  local private_tmp public_tmp

  mkdir -p "${OUT_DIR}"
  private_tmp="$(mktemp "${OUT_DIR}/admin.private.conf.tmp.XXXXXX")"
  public_tmp="$(mktemp "${OUT_DIR}/admin.public.conf.tmp.XXXXXX")"

  scp "${SSH_OPTS[@]}" "ubuntu@${CONTROL_PUB}:/home/ubuntu/.kube/config" "${private_tmp}" >/dev/null
  cp "${private_tmp}" "${public_tmp}"

  sed -i "s#server: https://.*:6443#server: https://${CONTROL_PRIV}:6443#" "${private_tmp}"
  sed -i "s#server: https://.*:6443#server: https://${CONTROL_PUB}:6443#" "${public_tmp}"

  mv "${private_tmp}" "${OUT_DIR}/admin.private.conf"
  mv "${public_tmp}" "${OUT_DIR}/admin.public.conf"
}

publish_lambda_kubeconfig() {
  local kubeconfig_path parameter_prefix server ca_data client_cert_data client_key_data

  kubeconfig_path="${OUT_DIR}/admin.private.conf"
  [[ -f "${kubeconfig_path}" ]] || {
    echo "Missing kubeconfig to publish: ${kubeconfig_path}"
    return 1
  }

  parameter_prefix="${LAMBDA_KUBECONFIG_PARAMETER_PREFIX%/}"
  server="$(awk '/server: https:\/\// {print $2; exit}' "${kubeconfig_path}")"
  ca_data="$(awk '/certificate-authority-data:/ {print $2; exit}' "${kubeconfig_path}")"
  client_cert_data="$(awk '/client-certificate-data:/ {print $2; exit}' "${kubeconfig_path}")"
  client_key_data="$(awk '/client-key-data:/ {print $2; exit}' "${kubeconfig_path}")"

  [[ -n "${server}" && -n "${ca_data}" && -n "${client_cert_data}" && -n "${client_key_data}" ]] || {
    echo "Failed to extract kubeconfig fields from ${kubeconfig_path}"
    return 1
  }

  aws ssm put-parameter \
    --region "${AWS_REGION}" \
    --name "${parameter_prefix}/server" \
    --type String \
    --overwrite \
    --value "${server}" >/dev/null
  aws ssm put-parameter \
    --region "${AWS_REGION}" \
    --name "${parameter_prefix}/certificate-authority-data" \
    --type String \
    --overwrite \
    --value "${ca_data}" >/dev/null
  aws ssm put-parameter \
    --region "${AWS_REGION}" \
    --name "${parameter_prefix}/client-certificate-data" \
    --type String \
    --overwrite \
    --value "${client_cert_data}" >/dev/null
  aws ssm put-parameter \
    --region "${AWS_REGION}" \
    --name "${parameter_prefix}/client-key-data" \
    --type String \
    --overwrite \
    --value "${client_key_data}" >/dev/null
}

wait_ssh(){
  local host="$1"
  for _ in {1..120}; do
    if ssh "${SSH_OPTS[@]}" -o ConnectTimeout=3 "ubuntu@${host}" true >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "SSH not ready: ${host}"
  return 1
}

detect_build_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    arm64|aarch64) echo "arm64" ;;
    *)
      echo "Unsupported architecture: $(uname -m)"
      exit 1
      ;;
  esac
}

derive_kubernetes_version() {
  if [[ -n "${KUBERNETES_VERSION:-}" ]]; then
    echo "${KUBERNETES_VERSION}"
    return 0
  fi

  if [[ -e "${K8S_DIR}/.git" ]]; then
    local described_version
    described_version="$(git -C "${K8S_DIR}" describe --tags --match='v*' --abbrev=14 HEAD 2>/dev/null || true)"
    if [[ "${described_version}" =~ ^(v[0-9]+\.[0-9]+\.[0-9]+([-.+][0-9A-Za-z.-]+)?) ]]; then
      echo "${BASH_REMATCH[1]}"
      return 0
    fi
  fi

  local cross_version

  cross_version="$(<"${K8S_DIR}/build/build-image/cross/VERSION")"
  if [[ "${cross_version}" =~ ^(v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?)(-go[0-9].*)?$ ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi

  echo "Unable to derive Kubernetes version from ${K8S_DIR}/build/build-image/cross/VERSION"
  exit 1
}

seed_kube_version_vars() {
  local derived_version

  if [[ -n "${KUBE_GIT_VERSION:-}" && "${KUBE_GIT_VERSION}" == "${KUBERNETES_VERSION}" ]]; then
    return 0
  fi

  derived_version="$(derive_kubernetes_version)"
  export KUBE_GIT_VERSION="${derived_version}"
  export KUBE_GIT_TREE_STATE="${KUBE_GIT_TREE_STATE:-archive}"

  if [[ "${derived_version}" =~ ^v([0-9]+)\.([0-9]+) ]]; then
    export KUBE_GIT_MAJOR="${KUBE_GIT_MAJOR:-${BASH_REMATCH[1]}}"
    export KUBE_GIT_MINOR="${KUBE_GIT_MINOR:-${BASH_REMATCH[2]}}"
  fi
}

build_k8s_binaries_local() {
  [[ -d "${K8S_DIR}" ]] || { echo "Missing kubernetes dir: ${K8S_DIR}"; exit 1; }

  local build_arch="${1:?build arch}"
  local bindir outtar
  bindir="${K8S_DIR}/_output/local/bin/linux/${build_arch}"

  echo "[*] Building kubeadm/kubectl/kubelet from ${K8S_DIR}" >&2
  seed_kube_version_vars
  make -C "${K8S_DIR}" WHAT="cmd/kubeadm cmd/kubectl cmd/kubelet" >/dev/null

  for f in kubeadm kubectl kubelet; do
    [[ -x "${bindir}/${f}" ]] || { echo "Missing built binary: ${bindir}/${f}"; exit 1; }
  done

  outtar="$(mktemp /tmp/k8s-node-bins-XXXXXX.tar.gz)"
  tar -C "${bindir}" -czf "${outtar}" kubeadm kubectl kubelet
  echo "${outtar}"
}

BOOTDIR="${SCRIPT_DIR}/_ec2_bootstrap"
mkdir -p "${BOOTDIR}"

cat > "${BOOTDIR}/bootstrap_common.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

GO_VERSION="${GO_VERSION:-1.24.6}"
AWS_REGION="${AWS_REGION:-us-east-1}"
CNI_PLUGINS_VERSION="${CNI_PLUGINS_VERSION:-v1.5.1}"

sudo swapoff -a || true
sudo sed -ri '/\sswap\s/s/^#?/#/' /etc/fstab || true

sudo modprobe overlay || true
sudo modprobe br_netfilter || true
cat <<SYS | sudo tee /etc/modules-load.d/k8s.conf >/dev/null
overlay
br_netfilter
SYS
cat <<SYS | sudo tee /etc/sysctl.d/99-k8s.conf >/dev/null
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
SYS
sudo sysctl --system >/dev/null

sudo apt-get update -yq
sudo apt-get install -yq \
  curl wget git jq ca-certificates apt-transport-https gnupg lsb-release unzip \
  containerd socat conntrack ebtables ethtool iptables arptables

ARCH="$(dpkg --print-architecture)"
cd /tmp

sudo rm -rf /usr/local/go
wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz"
sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-${ARCH}.tar.gz"
echo 'export PATH=/usr/local/go/bin:$PATH' | sudo tee /etc/profile.d/go.sh >/dev/null

AWSCLI_ARCH="x86_64"
if [[ "${ARCH}" == "arm64" || "${ARCH}" == "aarch64" ]]; then
  AWSCLI_ARCH="aarch64"
fi
rm -rf /tmp/aws /tmp/awscliv2.zip
curl -s "https://awscli.amazonaws.com/awscli-exe-linux-${AWSCLI_ARCH}.zip" -o awscliv2.zip
unzip -oq awscliv2.zip
sudo ./aws/install --update >/dev/null 2>&1 || true
echo "export AWS_REGION=${AWS_REGION}" | sudo tee /etc/profile.d/aws_region.sh >/dev/null

case "${ARCH}" in
  amd64) CNI_ARCH=amd64 ;;
  arm64) CNI_ARCH=arm64 ;;
  *) echo "Unsupported arch for CNI plugins: ${ARCH}"; exit 1 ;;
esac
curl -fsSL -o /tmp/cni-plugins.tgz \
  "https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGINS_VERSION}/cni-plugins-linux-${CNI_ARCH}-${CNI_PLUGINS_VERSION}.tgz"
sudo mkdir -p /opt/cni/bin
sudo tar -C /opt/cni/bin -xzf /tmp/cni-plugins.tgz

sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml >/dev/null
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
sudo systemctl enable --now containerd

sudo mkdir -p /etc/systemd/system/kubelet.service.d
cat <<UNIT | sudo tee /etc/systemd/system/kubelet.service >/dev/null
[Unit]
Description=kubelet
Documentation=https://kubernetes.io/docs/
After=network-online.target containerd.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/kubelet
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT

cat <<DROPIN | sudo tee /etc/systemd/system/kubelet.service.d/10-kubeadm.conf >/dev/null
[Service]
Environment="KUBELET_KUBECONFIG_ARGS=--bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf"
Environment="KUBELET_CONFIG_ARGS=--config=/var/lib/kubelet/config.yaml"
EnvironmentFile=-/var/lib/kubelet/kubeadm-flags.env
EnvironmentFile=-/etc/default/kubelet
ExecStart=
ExecStart=/usr/local/bin/kubelet \$KUBELET_KUBECONFIG_ARGS \$KUBELET_CONFIG_ARGS \$KUBELET_KUBEADM_ARGS \$KUBELET_EXTRA_ARGS
DROPIN

sudo mkdir -p /etc/default
echo 'KUBELET_EXTRA_ARGS=' | sudo tee /etc/default/kubelet >/dev/null

sudo systemctl daemon-reload
sudo systemctl enable kubelet
EOF
chmod +x "${BOOTDIR}/bootstrap_common.sh"

cat > "${BOOTDIR}/bootstrap_storage.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

STORAGE_PRIV="${1:?storage private IP}"
ETCD_VERSION="${ETCD_VERSION:-v3.5.15}"

ARCH="$(dpkg --print-architecture)"
case "${ARCH}" in
  amd64|arm64) ETCD_ARCH="${ARCH}" ;;
  *)
    echo "Unsupported architecture for etcd: ${ARCH}"
    exit 1
    ;;
esac

cd /tmp
wget -q "https://github.com/etcd-io/etcd/releases/download/${ETCD_VERSION}/etcd-${ETCD_VERSION}-linux-${ETCD_ARCH}.tar.gz"
tar -xzf "etcd-${ETCD_VERSION}-linux-${ETCD_ARCH}.tar.gz"
sudo mv "etcd-${ETCD_VERSION}-linux-${ETCD_ARCH}/etcd" /usr/local/bin/etcd
sudo mv "etcd-${ETCD_VERSION}-linux-${ETCD_ARCH}/etcdctl" /usr/local/bin/etcdctl

sudo mkdir -p /var/lib/etcd
cat <<SERVICE | sudo tee /etc/systemd/system/etcd.service >/dev/null
[Unit]
Description=etcd
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/etcd \
  --name storage-0 \
  --data-dir /var/lib/etcd \
  --listen-client-urls http://0.0.0.0:2379 \
  --advertise-client-urls http://${STORAGE_PRIV}:2379 \
  --listen-peer-urls http://${STORAGE_PRIV}:2380 \
  --initial-advertise-peer-urls http://${STORAGE_PRIV}:2380 \
  --initial-cluster storage-0=http://${STORAGE_PRIV}:2380 \
  --initial-cluster-state new
Restart=always
RestartSec=5
LimitNOFILE=40000

[Install]
WantedBy=multi-user.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable --now etcd
EOF
chmod +x "${BOOTDIR}/bootstrap_storage.sh"

cat > "${BOOTDIR}/bootstrap_controlplane.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CONTROL_PRIV="${1:?control private IP}"
CONTROL_PUB="${2:?control public IP}"
ETCD_ENDPOINT="${3:?etcd endpoint}"
POD_CIDR="${4:?pod cidr}"
SERVICE_CIDR="${5:?service cidr}"
PODGC_CONTROLLER_NAME="${6:?podgc controller name}"
JOB_CONTROLLER_NAME="${7:?job controller name}"
TTL_AFTER_FINISHED_CONTROLLER_NAME="${8:?ttl-after-finished controller name}"
NAMESPACE_CONTROLLER_NAME="${9:?namespace controller name}"
CNI_MANIFEST_URL="${10:?cni manifest url}"
CLUSTER_NAME="${11:?cluster name}"
SCHEDULER_MODE="${12:?scheduler mode}"
KUBERNETES_VERSION="${13:?kubernetes version}"

case "${SCHEDULER_MODE}" in
  normal|lambda) ;;
  *)
    echo "Invalid scheduler mode: ${SCHEDULER_MODE}"
    exit 1
    ;;
esac

sudo mkdir -p /usr/local/bin
sudo tar -C /usr/local/bin -xzf /home/ubuntu/k8s-binaries.tar.gz
sudo chmod +x /usr/local/bin/kubeadm /usr/local/bin/kubectl /usr/local/bin/kubelet

etcd_ready=0
for _ in {1..120}; do
  if curl -fsS "${ETCD_ENDPOINT}/health" | grep -q '"health":"true"'; then
    etcd_ready=1
    break
  fi
  sleep 2
done

if [[ "${etcd_ready}" != "1" ]]; then
  echo "External etcd never became healthy at ${ETCD_ENDPOINT}"
  exit 1
fi

cat <<CONFIG | tee /home/ubuntu/kubeadm-config.yaml >/dev/null
apiVersion: kubeadm.k8s.io/v1beta4
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: "${CONTROL_PRIV}"
  bindPort: 6443
nodeRegistration:
  name: "${CLUSTER_NAME}-control"
---
apiVersion: kubeadm.k8s.io/v1beta4
kind: ClusterConfiguration
clusterName: "${CLUSTER_NAME}"
kubernetesVersion: "${KUBERNETES_VERSION}"
apiServer:
  certSANs:
  - "${CONTROL_PUB}"
  - "${CONTROL_PRIV}"
etcd:
  external:
    endpoints:
    - "${ETCD_ENDPOINT}"
networking:
  podSubnet: "${POD_CIDR}"
  serviceSubnet: "${SERVICE_CIDR}"
CONFIG

if [[ ! -f /etc/kubernetes/admin.conf ]]; then
  sudo kubeadm init --config /home/ubuntu/kubeadm-config.yaml
else
  echo "[*] Control plane already initialized; reusing /etc/kubernetes/admin.conf"
fi

mkdir -p /home/ubuntu/.kube
sudo cp /etc/kubernetes/admin.conf /home/ubuntu/.kube/config
sudo chown -R ubuntu:ubuntu /home/ubuntu/.kube

if [[ "${SCHEDULER_MODE}" == "lambda" ]]; then
  if [[ -f /etc/kubernetes/manifests/kube-scheduler.yaml ]]; then
    sudo rm -f /etc/kubernetes/manifests/kube-scheduler.yaml
  fi

  disabled_controllers=(
    "${PODGC_CONTROLLER_NAME}"
    "${JOB_CONTROLLER_NAME}"
    "${TTL_AFTER_FINISHED_CONTROLLER_NAME}"
    "${NAMESPACE_CONTROLLER_NAME}"
  )
  required_controllers=(
    "bootstrapsigner"
    "tokencleaner"
  )
  controller_disable_args=()
  for controller in "${disabled_controllers[@]}"; do
    controller_disable_args+=("-${controller}")
  done
  controllers_flag="    - --controllers=*,$(IFS=,; echo "${required_controllers[*]}"),$(IFS=,; echo "${controller_disable_args[*]}")"
  sudo awk -v controllers_flag="${controllers_flag}" '
    /^[[:space:]]*- --controllers=/ {
      if (!replaced) {
        print controllers_flag
        replaced=1
      }
      waiting_after_manager=0
      next
    }
    /- kube-controller-manager$/ {
      print
      waiting_after_manager=1
      next
    }
    waiting_after_manager {
      if (!replaced) {
        print controllers_flag
        replaced=1
      }
      waiting_after_manager=0
    }
    { print }
    END {
      if (waiting_after_manager && !replaced) {
        print controllers_flag
      }
    }
  ' /etc/kubernetes/manifests/kube-controller-manager.yaml \
    | sudo tee /etc/kubernetes/manifests/kube-controller-manager.yaml.new >/dev/null
  sudo mv /etc/kubernetes/manifests/kube-controller-manager.yaml.new /etc/kubernetes/manifests/kube-controller-manager.yaml
fi

export KUBECONFIG=/etc/kubernetes/admin.conf
api_ready=0
for _ in {1..120}; do
  if sudo /usr/local/bin/kubectl --kubeconfig /etc/kubernetes/admin.conf get nodes >/dev/null 2>&1; then
    api_ready=1
    break
  fi
  sleep 2
done

if [[ "${api_ready}" != "1" ]]; then
  echo "Kubernetes API never became ready via /etc/kubernetes/admin.conf"
  exit 1
fi

sudo /usr/local/bin/kubectl --kubeconfig /etc/kubernetes/admin.conf apply -f "${CNI_MANIFEST_URL}"
sudo /usr/local/bin/kubectl --kubeconfig /etc/kubernetes/admin.conf taint nodes --all node-role.kubernetes.io/control-plane- >/dev/null 2>&1 || true

JOIN_CMD="$(sudo kubeadm token create --ttl 2h --print-join-command)"
JOIN_TOKEN_ID="$(printf '%s\n' "${JOIN_CMD}" | awk '
  /--token[[:space:]]+/ {
    for (i = 1; i <= NF; i++) {
      if ($i == "--token") {
        split($(i + 1), token_parts, ".")
        print token_parts[1]
        exit
      }
    }
  }
')"

if [[ -z "${JOIN_TOKEN_ID}" ]]; then
  echo "Failed to parse bootstrap token from kubeadm join command"
  exit 1
fi

signature_ready=0
for _ in {1..120}; do
  if sudo /usr/local/bin/kubectl --kubeconfig /etc/kubernetes/admin.conf -n kube-public get configmap cluster-info -o json \
    | jq -er --arg key "jws-kubeconfig-${JOIN_TOKEN_ID}" '.data[$key] // empty' >/dev/null; then
    signature_ready=1
    break
  fi
  sleep 2
done

if [[ "${signature_ready}" != "1" ]]; then
  echo "Bootstrap token signature never appeared in kube-public/cluster-info for token ID ${JOIN_TOKEN_ID}"
  exit 1
fi

printf '%s\n' "${JOIN_CMD}" | sudo tee /root/join-command.txt >/dev/null
sudo chmod 600 /root/join-command.txt
EOF
chmod +x "${BOOTDIR}/bootstrap_controlplane.sh"

cat > "${BOOTDIR}/bootstrap_worker.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

NODE_NAME="${1:?node name}"
JOIN_CMD_B64="${2:?base64 join command}"

sudo mkdir -p /usr/local/bin
sudo tar -C /usr/local/bin -xzf /home/ubuntu/k8s-binaries.tar.gz
sudo chmod +x /usr/local/bin/kubeadm /usr/local/bin/kubectl /usr/local/bin/kubelet

JOIN_CMD="$(printf '%s' "${JOIN_CMD_B64}" | base64 -d)"
sudo bash -lc "${JOIN_CMD} --node-name '${NODE_NAME}'"
EOF
chmod +x "${BOOTDIR}/bootstrap_worker.sh"

ALL_HOSTS=("${STORAGE_PUB}" "${CONTROL_PUB}")
CLUSTER_HOSTS=("${CONTROL_PUB}")
for i in $(seq 1 "${N_WORKERS}"); do
  eval "ALL_HOSTS+=(\"\${WORKER$(printf '%02d' "$i")_PUB}\")"
  eval "CLUSTER_HOSTS+=(\"\${WORKER$(printf '%02d' "$i")_PUB}\")"
done

echo "== nodes_setup =="
echo "Workers:        ${N_WORKERS}"
echo "Scheduler mode: ${SCHEDULER_MODE}"
echo "K8s version:    ${KUBERNETES_VERSION}"
echo "Storage(priv):  ${STORAGE_PRIV}"
echo "Control(priv):  ${CONTROL_PRIV}"
echo "Local repo:     ${REPO_LOCAL_DIR}"
echo "Kubernetes dir: ${K8S_DIR}"
echo "Out dir:        ${OUT_DIR}"
echo

echo "[*] Waiting for SSH on all nodes"
for h in "${ALL_HOSTS[@]}"; do
  wait_ssh "$h"
  prime_conn "$h"
done

LOCAL_BUILD_ARCH="$(detect_build_arch)"
KUBERNETES_VERSION="$(derive_kubernetes_version)"
K8S_BIN_TAR="$(build_k8s_binaries_local "${LOCAL_BUILD_ARCH}")"
LOCAL_KUBECTL="${K8S_DIR}/_output/local/bin/linux/${LOCAL_BUILD_ARCH}/kubectl"

echo "[*] Copying bootstrap scripts and binaries"
for h in "${ALL_HOSTS[@]}"; do
  scp_to "$h" "${BOOTDIR}/bootstrap_common.sh"
done
scp_to "${STORAGE_PUB}" "${BOOTDIR}/bootstrap_storage.sh"
scp_to "${CONTROL_PUB}" "${BOOTDIR}/bootstrap_controlplane.sh"
for i in $(seq 1 "${N_WORKERS}"); do
  pub_var="WORKER$(printf '%02d' "$i")_PUB"
  scp_to "${!pub_var}" "${BOOTDIR}/bootstrap_worker.sh"
done
for h in "${CLUSTER_HOSTS[@]}"; do
  scp_to "$h" "${K8S_BIN_TAR}"
  ssh_do "$h" "mv /home/ubuntu/$(basename "${K8S_BIN_TAR}") /home/ubuntu/k8s-binaries.tar.gz"
done

echo "[*] Installing common dependencies"
for h in "${ALL_HOSTS[@]}"; do
  ssh_do "$h" "sudo env GO_VERSION='${GO_VERSION}' AWS_REGION='${AWS_REGION}' CNI_PLUGINS_VERSION='${CNI_PLUGINS_VERSION}' ETCD_VERSION='${ETCD_VERSION}' bash /home/ubuntu/bootstrap_common.sh"
done

ETCD_ENDPOINT="http://${STORAGE_PRIV}:2379"

echo "[*] Initializing storage node"
ssh_do "${STORAGE_PUB}" "sudo env ETCD_VERSION='${ETCD_VERSION}' bash /home/ubuntu/bootstrap_storage.sh '${STORAGE_PRIV}'"

echo "[*] Initializing control plane"
set +e
ssh_do "${CONTROL_PUB}" "sudo bash /home/ubuntu/bootstrap_controlplane.sh '${CONTROL_PRIV}' '${CONTROL_PUB}' '${ETCD_ENDPOINT}' '${POD_CIDR}' '${SERVICE_CIDR}' '${PODGC_CONTROLLER_NAME}' '${JOB_CONTROLLER_NAME}' '${TTL_AFTER_FINISHED_CONTROLLER_NAME}' '${NAMESPACE_CONTROLLER_NAME}' '${CNI_MANIFEST_URL}' '${K8S_CLUSTER_NAME}' '${SCHEDULER_MODE}' '${KUBERNETES_VERSION}'"
controlplane_status=$?
set -e

if ssh_do "${CONTROL_PUB}" "test -f /home/ubuntu/.kube/config" >/dev/null 2>&1; then
  echo "[*] Refreshing kubeconfig outputs"
  refresh_kubeconfigs
  echo "[*] Publishing Lambda kubeconfig to SSM parameter prefix ${LAMBDA_KUBECONFIG_PARAMETER_PREFIX}"
  publish_lambda_kubeconfig
fi

if [[ "${controlplane_status}" -ne 0 ]]; then
  exit "${controlplane_status}"
fi

JOIN_CMD="$(ssh_do "${CONTROL_PUB}" "sudo cat /root/join-command.txt")"
JOIN_CMD_B64="$(printf '%s' "${JOIN_CMD}" | base64 | tr -d '\n')"

echo "[*] Joining workers"
for i in $(seq 1 "${N_WORKERS}"); do
  pub_var="WORKER$(printf '%02d' "$i")_PUB"
  name="${K8S_CLUSTER_NAME}-worker-$(printf '%02d' "$i")"
  ssh_do "${!pub_var}" "sudo bash /home/ubuntu/bootstrap_worker.sh '${name}' '${JOIN_CMD_B64}'"
done

echo "[*] Waiting for cluster nodes to register"
KUBECONFIG="${OUT_DIR}/admin.public.conf" "${LOCAL_KUBECTL}" get nodes -o wide

echo
echo "Storage etcd: ${ETCD_ENDPOINT}"
echo "Wrote ${OUT_DIR}/admin.private.conf"
echo "Wrote ${OUT_DIR}/admin.public.conf"
echo "Use: export KUBECONFIG=${OUT_DIR}/admin.public.conf"
