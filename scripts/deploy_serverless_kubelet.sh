#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/deploy_serverless_kubelet.sh [options]

Creates EC2 worker nodes and installs the patched serverless-mode kubelet on
them. The kubelet uses a static kubeconfig that talks directly to the Lambda
apiserver; it does not use kubeadm bootstrap, controller-manager CSR approval,
or watch-based apiserver pod config.

Default behavior creates 2 t3.large Ubuntu workers, then bootstraps kubelet.

Options:
  --host HOST             Existing worker public DNS/IP. Repeat to skip EC2 provisioning.
  -w, --workers N         Number of workers to create (default: 2).
  -b, --behavior MODE     CREATE or REPLACE worker instances (default: CREATE).
  --instance-type TYPE    EC2 instance type for created workers (default: t3.large).
  --root-volume-gb GB     Root EBS size for created workers (default: 64).
  -i, --identity-file     SSH private key for ubuntu@HOST.
  --user USER             SSH user (default: ubuntu).
  --kubeconfig PATH       Kubeconfig for the Lambda apiserver.
  --cluster-env PATH      Source worker hosts from an env file instead of provisioning.
  --skip-provision        Do not create EC2 instances; use --host or --cluster-env.
  --node-prefix PREFIX    Node name prefix (default: ${K8S_CLUSTER_NAME}-worker).
  --node-name NAME        Node name for a single --host run.
  --skip-build            Reuse an existing binary tarball.
  --bins-tar PATH         Tarball containing kubelet and kubectl.
  -h, --help              Show help.

Environment knobs:
  AWS_REGION                  AWS region (default: us-east-1)
  SERVERLESS_RESOURCE_PREFIX  Shared prefix for serverless resources
  TAG_PREFIX                  EC2 tag/name prefix (default: SERVERLESS_RESOURCE_PREFIX)
  OUT_DIR                     Output directory (default: _serverless_out)
  K8S_DIR                     Kubernetes checkout (default: ./kubernetes)
  BUILD_ARCH                  Kubelet target arch, amd64 or arm64 (default: amd64)
  POD_CIDR_PREFIX             Prefix for per-node /24 pod CIDRs (default: 10.244)
  CNI_PLUGINS_VERSION         CNI plugins version installed on the node
EOF
}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1"
    exit 1
  }
}

emit_env() {
  printf 'export %s=%q\n' "$1" "$2"
}

HOSTS=()
PROVISION_WORKERS=1
CLUSTER_ENV_CLI=""
IDENTITY_FILE="${IDENTITY_FILE:-$HOME/.ssh/2025_06_03.pem}"
IDENTITY_FILE_CLI=""
SSH_USER="${SSH_USER:-ubuntu}"
KUBECONFIG_PATH="${KUBECONFIG_PATH:-}"
CLUSTER_ENV="${CLUSTER_ENV:-}"
NODE_PREFIX="${NODE_PREFIX:-}"
NODE_PREFIX_CLI=""
NODE_NAME="${NODE_NAME:-}"
SKIP_BUILD=0
BINS_TAR="${BINS_TAR:-}"
N_WORKERS="${N_WORKERS:-2}"
BEHAVIOR="${BEHAVIOR:-CREATE}"
WORKER_INSTANCE_TYPE="${WORKER_INSTANCE_TYPE:-t3.large}"
ROOT_VOL_GB="${ROOT_VOL_GB:-64}"
VPC_CIDR="${VPC_CIDR:-10.52.0.0/16}"
SUBNET_CIDR="${SUBNET_CIDR:-10.52.1.0/24}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOSTS+=("$2"); PROVISION_WORKERS=0; shift 2 ;;
    -w|--workers) N_WORKERS="$2"; shift 2 ;;
    -b|--behavior) BEHAVIOR="${2^^}"; shift 2 ;;
    --instance-type) WORKER_INSTANCE_TYPE="$2"; shift 2 ;;
    --root-volume-gb) ROOT_VOL_GB="$2"; shift 2 ;;
    -i|--identity-file) IDENTITY_FILE="$2"; IDENTITY_FILE_CLI="$2"; shift 2 ;;
    --user) SSH_USER="$2"; shift 2 ;;
    --kubeconfig) KUBECONFIG_PATH="$2"; shift 2 ;;
    --cluster-env) CLUSTER_ENV="$2"; CLUSTER_ENV_CLI=1; PROVISION_WORKERS=0; shift 2 ;;
    --skip-provision) PROVISION_WORKERS=0; shift ;;
    --node-prefix) NODE_PREFIX="$2"; NODE_PREFIX_CLI="$2"; shift 2 ;;
    --node-name) NODE_NAME="$2"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --bins-tar) BINS_TAR="$2"; shift 2 ;;
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
OUT_DIR="${OUT_DIR:-${REPO_LOCAL_DIR}/_serverless_out}"
EC2_OUT_DIR="${EC2_OUT_DIR:-${REPO_LOCAL_DIR}/_ec2_out}"
K8S_DIR="${K8S_DIR:-${REPO_LOCAL_DIR}/kubernetes}"
KUBECONFIG_PATH="${KUBECONFIG_PATH:-${OUT_DIR}/lambda-apiserver.kubeconfig}"

AWS_REGION="${AWS_REGION:-us-east-1}"
SERVERLESS_RESOURCE_PREFIX="${SERVERLESS_RESOURCE_PREFIX:-ctrlless-serverless}"
TAG_PREFIX="${TAG_PREFIX:-${SERVERLESS_RESOURCE_PREFIX}}"
K8S_CLUSTER_NAME="${K8S_CLUSTER_NAME:-${TAG_PREFIX}}"
KEY_NAME="${KEY_NAME:-$(basename "${IDENTITY_FILE}" .pem)}"
ROLE_NAME="${ROLE_NAME:-${TAG_PREFIX}-worker-role}"
INSTANCE_PROFILE_NAME="${INSTANCE_PROFILE_NAME:-${TAG_PREFIX}-worker-instance-profile}"
WORKER_ENV="${WORKER_ENV:-${OUT_DIR}/workers.env}"
POD_CIDR_PREFIX="${POD_CIDR_PREFIX:-10.244}"
CNI_PLUGINS_VERSION="${CNI_PLUGINS_VERSION:-v1.5.1}"
KUBERNETES_VERSION="${KUBERNETES_VERSION:-v1.33.1}"
BUILD_ARCH="${BUILD_ARCH:-amd64}"
CLUSTER_DNS="${CLUSTER_DNS:-}"
CLUSTER_DOMAIN="${CLUSTER_DOMAIN:-cluster.local}"
PAUSE_IMAGE="${PAUSE_IMAGE:-registry.k8s.io/pause:3.10}"

export AWS_REGION

need ssh
need scp
need tar
if [[ "${SKIP_BUILD}" != "1" ]]; then
  need make
fi
if [[ "${PROVISION_WORKERS}" == "1" ]]; then
  need aws
  need ssh-keygen
  need curl
fi

[[ -f "${KUBECONFIG_PATH}" ]] || { echo "Missing kubeconfig: ${KUBECONFIG_PATH}"; exit 1; }
[[ -x "${SCRIPT_DIR}/_ec2_bootstrap/bootstrap_serverless_worker.sh" ]] || { echo "Missing worker bootstrap script."; exit 1; }

case "${BEHAVIOR}" in
  CREATE|REPLACE) ;;
  *)
    echo "Invalid BEHAVIOR=${BEHAVIOR}. Use CREATE or REPLACE."
    exit 1
    ;;
esac

lookup_tag() {
  local svc_op="$1" key="$2" val="$3" query="$4"
  # shellcheck disable=SC2086
  aws ${svc_op} \
    --region "${AWS_REGION}" \
    --filters "Name=tag:${key},Values=${val}" \
    --query "${query}" \
    --output text 2>/dev/null || true
}

list_worker_instance_ids() {
  aws ec2 describe-instances \
    --region "${AWS_REGION}" \
    --filters "Name=tag:Project,Values=${TAG_PREFIX}" \
              "Name=tag:Role,Values=serverless-worker" \
              "Name=instance-state-name,Values=pending,running,stopping,stopped" \
    --query 'Reservations[].Instances[].InstanceId' \
    --output text 2>/dev/null || true
}

terminate_existing_workers() {
  local ids_txt ids=()
  ids_txt="$(list_worker_instance_ids)"
  [[ -z "${ids_txt}" || "${ids_txt}" == "None" ]] && return 0
  read -r -a ids <<<"${ids_txt}"
  [[ ${#ids[@]} -gt 0 ]] || return 0

  echo "[*] Terminating existing serverless worker instances: ${ids[*]}"
  aws ec2 terminate-instances --region "${AWS_REGION}" --instance-ids "${ids[@]}" >/dev/null
  aws ec2 wait instance-terminated --region "${AWS_REGION}" --instance-ids "${ids[@]}"
}

ensure_no_existing_workers() {
  local ids_txt
  ids_txt="$(list_worker_instance_ids)"
  if [[ -n "${ids_txt}" && "${ids_txt}" != "None" ]]; then
    echo "Existing serverless workers found for tag prefix ${TAG_PREFIX}: ${ids_txt}"
    echo "Use --behavior REPLACE to roll them over, or use --cluster-env/--host to reuse them."
    exit 1
  fi
}

ensure_worker_key_pair() {
  if ! aws ec2 describe-key-pairs --region "${AWS_REGION}" --key-names "${KEY_NAME}" >/dev/null 2>&1; then
    echo "[*] Importing EC2 key pair ${KEY_NAME}"
    aws ec2 import-key-pair \
      --region "${AWS_REGION}" \
      --key-name "${KEY_NAME}" \
      --public-key-material "$(ssh-keygen -y -f "${IDENTITY_FILE}")" >/dev/null
  fi
}

ensure_worker_iam() {
  local trust_policy role_in_profile
  trust_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

  if ! aws iam get-role --role-name "${ROLE_NAME}" >/dev/null 2>&1; then
    echo "[*] Creating IAM role ${ROLE_NAME}"
    aws iam create-role \
      --role-name "${ROLE_NAME}" \
      --assume-role-policy-document "${trust_policy}" >/dev/null
  else
    echo "[*] Reusing IAM role ${ROLE_NAME}"
  fi

  aws iam attach-role-policy \
    --role-name "${ROLE_NAME}" \
    --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly >/dev/null 2>&1 || true

  if ! aws iam get-instance-profile --instance-profile-name "${INSTANCE_PROFILE_NAME}" >/dev/null 2>&1; then
    echo "[*] Creating instance profile ${INSTANCE_PROFILE_NAME}"
    aws iam create-instance-profile \
      --instance-profile-name "${INSTANCE_PROFILE_NAME}" >/dev/null
  else
    echo "[*] Reusing instance profile ${INSTANCE_PROFILE_NAME}"
  fi

  role_in_profile="$(
    aws iam get-instance-profile \
      --instance-profile-name "${INSTANCE_PROFILE_NAME}" \
      --query 'InstanceProfile.Roles[0].RoleName' \
      --output text 2>/dev/null || true
  )"
  if [[ "${role_in_profile}" != "${ROLE_NAME}" ]]; then
    if [[ -n "${role_in_profile}" && "${role_in_profile}" != "None" ]]; then
      aws iam remove-role-from-instance-profile \
        --instance-profile-name "${INSTANCE_PROFILE_NAME}" \
        --role-name "${role_in_profile}" >/dev/null || true
    fi
    aws iam add-role-to-instance-profile \
      --instance-profile-name "${INSTANCE_PROFILE_NAME}" \
      --role-name "${ROLE_NAME}" >/dev/null
  fi

  echo "[*] Waiting for instance profile ${INSTANCE_PROFILE_NAME}"
  for _ in {1..30}; do
    if [[ "$(
      aws iam get-instance-profile \
        --instance-profile-name "${INSTANCE_PROFILE_NAME}" \
        --query 'InstanceProfile.Roles[0].RoleName' \
        --output text 2>/dev/null || true
    )" == "${ROLE_NAME}" ]]; then
      return 0
    fi
    sleep 2
  done
  echo "Timeout waiting for instance profile ${INSTANCE_PROFILE_NAME}"
  exit 1
}

sync_cidr_port() {
  local sg_id="$1" port="$2" cidr="$3"
  local existing
  existing="$(
    aws ec2 describe-security-groups \
      --region "${AWS_REGION}" \
      --group-ids "${sg_id}" \
      --query "SecurityGroups[0].IpPermissions[?FromPort==\`${port}\` && ToPort==\`${port}\` && IpProtocol=='tcp'].IpRanges[].CidrIp" \
      --output text 2>/dev/null || true
  )"

  for old_cidr in ${existing}; do
    if [[ "${old_cidr}" != "${cidr}" ]]; then
      aws ec2 revoke-security-group-ingress \
        --region "${AWS_REGION}" \
        --group-id "${sg_id}" \
        --protocol tcp \
        --port "${port}" \
        --cidr "${old_cidr}" >/dev/null 2>&1 || true
    fi
  done

  aws ec2 authorize-security-group-ingress \
    --region "${AWS_REGION}" \
    --group-id "${sg_id}" \
    --protocol tcp \
    --port "${port}" \
    --cidr "${cidr}" >/dev/null 2>&1 || true
}

ensure_worker_network() {
  local my_ip ssh_cidr vpc_id igw_id rt_id subnet_id sg_id az assoc_id cur_rt have_rule

  my_ip="$(curl -s https://checkip.amazonaws.com || true)"
  ssh_cidr="${SSH_CIDR:-${my_ip:+${my_ip}/32}}"
  ssh_cidr="${ssh_cidr:-0.0.0.0/0}"

  vpc_id="$(lookup_tag 'ec2 describe-vpcs' 'Name' "${TAG_PREFIX}-vpc" 'Vpcs[0].VpcId')"
  if [[ -z "${vpc_id}" || "${vpc_id}" == "None" ]]; then
    echo "[*] Creating VPC ${TAG_PREFIX}-vpc"
    vpc_id="$(aws ec2 create-vpc --region "${AWS_REGION}" --cidr-block "${VPC_CIDR}" --query 'Vpc.VpcId' --output text)"
    aws ec2 create-tags --region "${AWS_REGION}" --resources "${vpc_id}" --tags "Key=Name,Value=${TAG_PREFIX}-vpc" "Key=Project,Value=${TAG_PREFIX}" >/dev/null
    aws ec2 modify-vpc-attribute --region "${AWS_REGION}" --vpc-id "${vpc_id}" --enable-dns-hostnames
  fi

  igw_id="$(lookup_tag 'ec2 describe-internet-gateways' 'Name' "${TAG_PREFIX}-igw" 'InternetGateways[0].InternetGatewayId')"
  if [[ -z "${igw_id}" || "${igw_id}" == "None" ]]; then
    echo "[*] Creating Internet gateway ${TAG_PREFIX}-igw"
    igw_id="$(aws ec2 create-internet-gateway --region "${AWS_REGION}" --query 'InternetGateway.InternetGatewayId' --output text)"
    aws ec2 create-tags --region "${AWS_REGION}" --resources "${igw_id}" --tags "Key=Name,Value=${TAG_PREFIX}-igw" "Key=Project,Value=${TAG_PREFIX}" >/dev/null
    aws ec2 attach-internet-gateway --region "${AWS_REGION}" --internet-gateway-id "${igw_id}" --vpc-id "${vpc_id}" >/dev/null 2>&1 || true
  fi

  rt_id="$(lookup_tag 'ec2 describe-route-tables' 'Name' "${TAG_PREFIX}-rt" 'RouteTables[0].RouteTableId')"
  if [[ -z "${rt_id}" || "${rt_id}" == "None" ]]; then
    echo "[*] Creating route table ${TAG_PREFIX}-rt"
    rt_id="$(aws ec2 create-route-table --region "${AWS_REGION}" --vpc-id "${vpc_id}" --query 'RouteTable.RouteTableId' --output text)"
    aws ec2 create-tags --region "${AWS_REGION}" --resources "${rt_id}" --tags "Key=Name,Value=${TAG_PREFIX}-rt" "Key=Project,Value=${TAG_PREFIX}" >/dev/null
    aws ec2 create-route --region "${AWS_REGION}" --route-table-id "${rt_id}" --destination-cidr-block 0.0.0.0/0 --gateway-id "${igw_id}" >/dev/null 2>&1 || true
  fi

  subnet_id="$(lookup_tag 'ec2 describe-subnets' 'Name' "${TAG_PREFIX}-subnet" 'Subnets[0].SubnetId')"
  if [[ -z "${subnet_id}" || "${subnet_id}" == "None" ]]; then
    echo "[*] Creating subnet ${TAG_PREFIX}-subnet"
    az="$(
      aws ec2 describe-availability-zones \
        --region "${AWS_REGION}" \
        --query 'AvailabilityZones[?State==`available`].ZoneName | [0]' \
        --output text
    )"
    subnet_id="$(
      aws ec2 create-subnet \
        --region "${AWS_REGION}" \
        --vpc-id "${vpc_id}" \
        --cidr-block "${SUBNET_CIDR}" \
        --availability-zone "${az}" \
        --query 'Subnet.SubnetId' \
        --output text
    )"
    aws ec2 create-tags --region "${AWS_REGION}" --resources "${subnet_id}" --tags "Key=Name,Value=${TAG_PREFIX}-subnet" "Key=Project,Value=${TAG_PREFIX}" >/dev/null
    aws ec2 modify-subnet-attribute --region "${AWS_REGION}" --subnet-id "${subnet_id}" --map-public-ip-on-launch
  fi

  if [[ "$(
    aws ec2 describe-subnets \
      --region "${AWS_REGION}" \
      --subnet-ids "${subnet_id}" \
      --query 'Subnets[0].MapPublicIpOnLaunch' \
      --output text
  )" != "True" ]]; then
    aws ec2 modify-subnet-attribute --region "${AWS_REGION}" --subnet-id "${subnet_id}" --map-public-ip-on-launch
  fi

  cur_rt="$(aws ec2 describe-route-tables \
    --region "${AWS_REGION}" \
    --filters "Name=association.subnet-id,Values=${subnet_id}" \
    --query 'RouteTables[0].RouteTableId' --output text 2>/dev/null || true)"
  if [[ -z "${cur_rt}" || "${cur_rt}" == "None" || "${cur_rt}" != "${rt_id}" ]]; then
    assoc_id="$(aws ec2 describe-route-tables \
      --region "${AWS_REGION}" \
      --filters "Name=association.subnet-id,Values=${subnet_id}" \
      --query 'RouteTables[0].Associations[0].RouteTableAssociationId' --output text 2>/dev/null || true)"
    if [[ -n "${assoc_id}" && "${assoc_id}" != "None" ]]; then
      aws ec2 replace-route-table-association --region "${AWS_REGION}" --association-id "${assoc_id}" --route-table-id "${rt_id}" >/dev/null
    else
      aws ec2 associate-route-table --region "${AWS_REGION}" --route-table-id "${rt_id}" --subnet-id "${subnet_id}" >/dev/null
    fi
  fi

  sg_id="$(lookup_tag 'ec2 describe-security-groups' 'Name' "${TAG_PREFIX}-workers-sg" 'SecurityGroups[0].GroupId')"
  if [[ -z "${sg_id}" || "${sg_id}" == "None" ]]; then
    echo "[*] Creating security group ${TAG_PREFIX}-workers-sg"
    sg_id="$(aws ec2 create-security-group \
      --region "${AWS_REGION}" \
      --group-name "${TAG_PREFIX}-workers-sg" \
      --description "${TAG_PREFIX} serverless workers" \
      --vpc-id "${vpc_id}" \
      --query 'GroupId' \
      --output text)"
    aws ec2 create-tags --region "${AWS_REGION}" --resources "${sg_id}" --tags "Key=Name,Value=${TAG_PREFIX}-workers-sg" "Key=Project,Value=${TAG_PREFIX}" >/dev/null
  fi

  have_rule="$(
    aws ec2 describe-security-groups \
      --region "${AWS_REGION}" \
      --group-ids "${sg_id}" \
      --query "SecurityGroups[0].IpPermissions[?UserIdGroupPairs[?GroupId=='${sg_id}']] | length(@)" \
      --output text 2>/dev/null || echo 0
  )"
  if [[ "${have_rule}" == "0" ]]; then
    aws ec2 authorize-security-group-ingress \
      --region "${AWS_REGION}" \
      --group-id "${sg_id}" \
      --protocol -1 \
      --source-group "${sg_id}" >/dev/null
  fi
  sync_cidr_port "${sg_id}" 22 "${ssh_cidr}"

  VPC_ID="${vpc_id}"
  RT_ID="${rt_id}"
  SUBNET_ID="${subnet_id}"
  SG_ID="${sg_id}"
  SSH_CIDR="${ssh_cidr}"
}

resolve_worker_ami() {
  local ami_id
  ami_id="$(
    aws ssm get-parameters \
      --region "${AWS_REGION}" \
      --names "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id" \
      --query 'Parameters[0].Value' \
      --output text 2>/dev/null || true
  )"
  if [[ -z "${ami_id}" || "${ami_id}" == "None" ]]; then
    ami_id="$(
      aws ec2 describe-images \
        --region "${AWS_REGION}" \
        --owners 099720109477 \
        --filters \
          "Name=name,Values=ubuntu/images/*/ubuntu-noble-24.04-amd64-server-*" \
          "Name=state,Values=available" \
          "Name=architecture,Values=x86_64" \
          "Name=root-device-type,Values=ebs" \
          "Name=virtualization-type,Values=hvm" \
        --query 'Images | sort_by(@,&CreationDate)[-1].ImageId' \
        --output text
    )"
  fi
  [[ -n "${ami_id}" && "${ami_id}" != "None" ]] || { echo "No Ubuntu 24.04 AMI found"; exit 1; }
  echo "${ami_id}"
}

run_worker_instance() {
  local name="$1"
  aws ec2 run-instances \
    --region "${AWS_REGION}" \
    --image-id "${AMI_ID}" \
    --instance-type "${WORKER_INSTANCE_TYPE}" \
    --key-name "${KEY_NAME}" \
    --subnet-id "${SUBNET_ID}" \
    --security-group-ids "${SG_ID}" \
    --associate-public-ip-address \
    --iam-instance-profile Name="${INSTANCE_PROFILE_NAME}" \
    --block-device-mappings "[{\"DeviceName\":\"/dev/sda1\",\"Ebs\":{\"DeleteOnTermination\":true,\"VolumeSize\":${ROOT_VOL_GB},\"VolumeType\":\"gp3\"}}]" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${name}},{Key=Project,Value=${TAG_PREFIX}},{Key=Role,Value=serverless-worker},{Key=ControlPlane,Value=serverless}]" \
    --query 'Instances[0].InstanceId' \
    --output text
}

instance_private_ip() {
  aws ec2 describe-instances \
    --region "${AWS_REGION}" \
    --instance-ids "$1" \
    --query 'Reservations[0].Instances[0].PrivateIpAddress' \
    --output text
}

instance_public_ip() {
  aws ec2 describe-instances \
    --region "${AWS_REGION}" \
    --instance-ids "$1" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text
}

provision_workers() {
  local worker_ids=() worker_privs=() worker_pubs=() ids=()
  [[ -n "${IDENTITY_FILE}" && -f "${IDENTITY_FILE}" ]] || { echo "Missing SSH identity file. Use -i/--identity-file."; exit 1; }

  echo "== provision serverless workers =="
  echo "Region:        ${AWS_REGION}"
  echo "Workers:       ${N_WORKERS}"
  echo "Behavior:      ${BEHAVIOR}"
  echo "Instance type: ${WORKER_INSTANCE_TYPE}"
  echo "Key:           ${KEY_NAME} (${IDENTITY_FILE})"
  echo "Tag prefix:    ${TAG_PREFIX}"
  echo

  ensure_worker_key_pair
  ensure_worker_iam

  case "${BEHAVIOR}" in
    REPLACE) terminate_existing_workers ;;
    CREATE) ensure_no_existing_workers ;;
  esac

  ensure_worker_network
  AMI_ID="$(resolve_worker_ami)"

  echo "[*] Launching ${N_WORKERS} worker instance(s)"
  for i in $(seq 1 "${N_WORKERS}"); do
    worker_ids+=("$(run_worker_instance "$(printf '%s-worker-%02d' "${K8S_CLUSTER_NAME}" "${i}")")")
  done

  ids=("${worker_ids[@]}")
  aws ec2 wait instance-status-ok --region "${AWS_REGION}" --instance-ids "${ids[@]}"

  HOSTS=()
  for id in "${worker_ids[@]}"; do
    local priv_ip pub_ip
    priv_ip="$(instance_private_ip "${id}")"
    pub_ip="$(instance_public_ip "${id}")"
    worker_privs+=("${priv_ip}")
    worker_pubs+=("${pub_ip}")
    HOSTS+=("${pub_ip}")
  done

  mkdir -p "${OUT_DIR}"
  {
    emit_env AWS_REGION "${AWS_REGION}"
    emit_env SERVERLESS_RESOURCE_PREFIX "${SERVERLESS_RESOURCE_PREFIX}"
    emit_env TAG_PREFIX "${TAG_PREFIX}"
    emit_env K8S_CLUSTER_NAME "${K8S_CLUSTER_NAME}"
    emit_env KUBERNETES_VERSION "${KUBERNETES_VERSION}"
    emit_env REPO_LOCAL_DIR "${REPO_LOCAL_DIR}"
    emit_env K8S_DIR "${K8S_DIR}"
    emit_env OUT_DIR "${OUT_DIR}"
    emit_env WORKER_ENV "${WORKER_ENV}"
    emit_env VPC_ID "${VPC_ID}"
    emit_env RT_ID "${RT_ID}"
    emit_env SUBNET_ID "${SUBNET_ID}"
    emit_env SG_ID "${SG_ID}"
    emit_env AMI_ID "${AMI_ID}"
    emit_env KEY_NAME "${KEY_NAME}"
    emit_env IDENTITY_FILE "${IDENTITY_FILE}"
    emit_env ROLE_NAME "${ROLE_NAME}"
    emit_env INSTANCE_PROFILE_NAME "${INSTANCE_PROFILE_NAME}"
    emit_env VPC_CIDR "${VPC_CIDR}"
    emit_env SUBNET_CIDR "${SUBNET_CIDR}"
    emit_env SSH_CIDR "${SSH_CIDR}"
    emit_env N_WORKERS "${N_WORKERS}"
    emit_env WORKER_INSTANCE_TYPE "${WORKER_INSTANCE_TYPE}"
    emit_env ROOT_VOL_GB "${ROOT_VOL_GB}"
    emit_env WORKER_IDS "${worker_ids[*]}"
    local idx=1
    for ((i=0; i<${#worker_ids[@]}; i++)); do
      printf 'export WORKER%02d_ID=%q\n' "${idx}" "${worker_ids[$i]}"
      printf 'export WORKER%02d_PRIV=%q\n' "${idx}" "${worker_privs[$i]}"
      printf 'export WORKER%02d_PUB=%q\n' "${idx}" "${worker_pubs[$i]}"
      idx=$((idx + 1))
    done
  } > "${WORKER_ENV}"

  echo
  echo "Wrote ${WORKER_ENV}"
  for ((i=0; i<${#worker_ids[@]}; i++)); do
    printf "  worker-%02d: %s (pub %s)\n" "$((i + 1))" "${worker_privs[$i]}" "${worker_pubs[$i]}"
  done
}

load_hosts_from_env() {
  local env_path="$1"
  local saved_out_dir="${OUT_DIR}"
  local saved_kubeconfig_path="${KUBECONFIG_PATH}"

  [[ -f "${env_path}" ]] || { echo "Missing cluster env: ${env_path}"; exit 1; }
  # shellcheck source=/dev/null
  source "${env_path}"
  OUT_DIR="${saved_out_dir}"
  KUBECONFIG_PATH="${saved_kubeconfig_path}"
  if [[ -n "${IDENTITY_FILE_CLI}" ]]; then
    IDENTITY_FILE="${IDENTITY_FILE_CLI}"
  fi
  if [[ -n "${NODE_PREFIX_CLI}" ]]; then
    NODE_PREFIX="${NODE_PREFIX_CLI}"
  else
    NODE_PREFIX="${K8S_CLUSTER_NAME:-${TAG_PREFIX}}-worker"
  fi

  HOSTS=()
  while IFS= read -r var_name; do
    HOSTS+=("${!var_name}")
  done < <(compgen -A variable | grep -E '^WORKER[0-9]+_PUB$' | sort || true)
}

if [[ "${PROVISION_WORKERS}" == "1" ]]; then
  provision_workers
elif [[ ${#HOSTS[@]} -eq 0 ]]; then
  if [[ -z "${CLUSTER_ENV}" ]]; then
    if [[ -f "${WORKER_ENV}" ]]; then
      CLUSTER_ENV="${WORKER_ENV}"
    else
      CLUSTER_ENV="${EC2_OUT_DIR}/cluster.env"
    fi
  fi
  load_hosts_from_env "${CLUSTER_ENV}"
elif [[ -n "${CLUSTER_ENV_CLI}" ]]; then
  load_hosts_from_env "${CLUSTER_ENV}"
fi

NODE_PREFIX="${NODE_PREFIX:-${K8S_CLUSTER_NAME}-worker}"

[[ ${#HOSTS[@]} -gt 0 ]] || { echo "No worker hosts available."; exit 1; }
[[ -n "${IDENTITY_FILE}" && -f "${IDENTITY_FILE}" ]] || { echo "Missing SSH identity file. Use -i/--identity-file."; exit 1; }
if [[ -n "${NODE_NAME}" && ${#HOSTS[@]} -ne 1 ]]; then
  echo "--node-name can only be used with exactly one --host"
  exit 1
fi

SOCK_DIR="${SOCK_DIR:-${REPO_LOCAL_DIR}/_ssh_mux}"
mkdir -p "${SOCK_DIR}" "${OUT_DIR}"
SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o IdentitiesOnly=yes
  -o PreferredAuthentications=publickey
  -i "${IDENTITY_FILE}"
  -o ControlMaster=auto
  -o ControlPath="${SOCK_DIR}/%r@%h:%p"
  -o ControlPersist=600
)

ssh_do() {
  local host="$1"; shift
  ssh "${SSH_OPTS[@]}" "${SSH_USER}@${host}" "$@"
}

scp_to() {
  local host="$1"; shift
  scp "${SSH_OPTS[@]}" "$@" "${SSH_USER}@${host}:/home/${SSH_USER}/"
}

wait_ssh() {
  local host="$1"
  for _ in {1..120}; do
    if ssh "${SSH_OPTS[@]}" -o ConnectTimeout=3 "${SSH_USER}@${host}" true >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "SSH not ready: ${host}"
  return 1
}

detect_build_arch() {
  case "${BUILD_ARCH}" in
    amd64|arm64) echo "${BUILD_ARCH}" ;;
    local)
      case "$(uname -m)" in
        x86_64|amd64) echo "amd64" ;;
        arm64|aarch64) echo "arm64" ;;
        *)
          echo "Unsupported local architecture: $(uname -m)"
          exit 1
          ;;
      esac
      ;;
    *)
      echo "Unsupported BUILD_ARCH=${BUILD_ARCH}. Use amd64, arm64, or local."
      exit 1
      ;;
  esac
}

seed_kube_version_vars() {
  export KUBE_GIT_VERSION="${KUBE_GIT_VERSION:-${KUBERNETES_VERSION}}"
  export KUBE_GIT_TREE_STATE="${KUBE_GIT_TREE_STATE:-archive}"
  if [[ "${KUBE_GIT_VERSION}" =~ ^v([0-9]+)\.([0-9]+) ]]; then
    export KUBE_GIT_MAJOR="${KUBE_GIT_MAJOR:-${BASH_REMATCH[1]}}"
    export KUBE_GIT_MINOR="${KUBE_GIT_MINOR:-${BASH_REMATCH[2]}}"
  fi
}

build_kubelet_tar() {
  local build_arch bindir outtar
  build_arch="$(detect_build_arch)"
  bindir="${K8S_DIR}/_output/local/bin/linux/${build_arch}"

  [[ -d "${K8S_DIR}" ]] || { echo "Missing Kubernetes dir: ${K8S_DIR}"; exit 1; }
  seed_kube_version_vars
  echo "[*] Building kubelet and kubectl from ${K8S_DIR}" >&2
  KUBE_BUILD_PLATFORMS="linux/${build_arch}" \
    make -C "${K8S_DIR}" WHAT="cmd/kubelet cmd/kubectl" >&2

  for bin in kubelet kubectl; do
    [[ -x "${bindir}/${bin}" ]] || { echo "Missing built binary: ${bindir}/${bin}"; exit 1; }
  done

  outtar="${OUT_DIR}/serverless-kubelet-bins-${build_arch}.tar.gz"
  tar -C "${bindir}" -czf "${outtar}" kubelet kubectl
  echo "${outtar}"
}

if [[ "${SKIP_BUILD}" == "1" ]]; then
  [[ -n "${BINS_TAR}" && -f "${BINS_TAR}" ]] || { echo "--skip-build requires --bins-tar PATH"; exit 1; }
else
  BINS_TAR="$(build_kubelet_tar)"
fi

echo "== serverless kubelet bootstrap =="
echo "Workers:       ${HOSTS[*]}"
echo "Identity:      ${IDENTITY_FILE}"
echo "Kubeconfig:    ${KUBECONFIG_PATH}"
echo "Binary tar:    ${BINS_TAR}"
echo "Node prefix:   ${NODE_PREFIX}"
echo "Pod CIDRs:     ${POD_CIDR_PREFIX}.<worker-index>.0/24"
echo

idx=1
for host in "${HOSTS[@]}"; do
  wait_ssh "${host}"

  node_name="${NODE_NAME:-$(printf '%s-%02d' "${NODE_PREFIX}" "${idx}")}"
  node_pod_cidr="${POD_CIDR_PREFIX}.${idx}.0/24"

  echo "[*] Uploading kubelet payload to ${host} as node ${node_name}"
  scp_to "${host}" \
    "${BINS_TAR}" \
    "${KUBECONFIG_PATH}" \
    "${SCRIPT_DIR}/_ec2_bootstrap/bootstrap_serverless_worker.sh"

  echo "[*] Bootstrapping serverless kubelet on ${host}"
  ssh_do "${host}" \
    "sudo env CNI_PLUGINS_VERSION='${CNI_PLUGINS_VERSION}' CLUSTER_DNS='${CLUSTER_DNS}' CLUSTER_DOMAIN='${CLUSTER_DOMAIN}' PAUSE_IMAGE='${PAUSE_IMAGE}' bash /home/${SSH_USER}/bootstrap_serverless_worker.sh '${node_name}' '${node_pod_cidr}' '/home/${SSH_USER}/$(basename "${KUBECONFIG_PATH}")' '/home/${SSH_USER}/$(basename "${BINS_TAR}")'"

  idx=$((idx + 1))
done

echo
echo "Serverless kubelet bootstrap complete."
