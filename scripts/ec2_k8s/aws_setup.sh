#!/usr/bin/env bash
set -euo pipefail

# Provisions:
# - VPC/Subnet/IGW/RouteTable/SecurityGroup
# - EC2 KeyPair import from local IDENTITY_FILE
# - IAM Role + Instance Profile for nodes
# - 1 storage instance for etcd, 1 control-plane instance, and N worker instances
#
# Outputs: ${OUT_DIR}/cluster.env

N_WORKERS="${N_WORKERS:-2}"
BEHAVIOR="${BEHAVIOR:-CREATE}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -w|--workers)  N_WORKERS="$2"; shift 2 ;;
    -b|--behavior) BEHAVIOR="${2^^}"; shift 2 ;;
    *)
      echo "Unknown arg: $1"
      exit 1
      ;;
  esac
done

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing $1"; exit 1; }; }
need aws
need jq
need ssh-keygen
need curl

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_LOCAL_DIR="${REPO_LOCAL_DIR:-$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel 2>/dev/null || (cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd))}"
OUT_DIR="${OUT_DIR:-${REPO_LOCAL_DIR}/_ec2_out}"

AWS_REGION="${AWS_REGION:-us-east-1}"
SCHEDULER_MODE="${SCHEDULER_MODE:-normal}"
TAG_PREFIX="${TAG_PREFIX:-ctrlless}"
K8S_CLUSTER_NAME="${K8S_CLUSTER_NAME:-${TAG_PREFIX}}"
LAMBDA_RESOURCE_PREFIX="${LAMBDA_RESOURCE_PREFIX:-${TAG_PREFIX}-lambda}"
LAMBDA_KUBECONFIG_PARAMETER_PREFIX="${LAMBDA_KUBECONFIG_PARAMETER_PREFIX:-/${LAMBDA_RESOURCE_PREFIX}/admin-private-kubeconfig}"
KUBERNETES_VERSION="${KUBERNETES_VERSION:-v1.33.1}"
PODGC_CONTROLLER_NAME="${PODGC_CONTROLLER_NAME:-pod-garbage-collector-controller}"
POD_CIDR="${POD_CIDR:-10.244.0.0/16}"
SERVICE_CIDR="${SERVICE_CIDR:-10.96.0.0/12}"
CNI_MANIFEST_URL="${CNI_MANIFEST_URL:-https://raw.githubusercontent.com/flannel-io/flannel/master/Documentation/kube-flannel.yml}"
CNI_PLUGINS_VERSION="${CNI_PLUGINS_VERSION:-v1.5.1}"
VPC_CIDR="${VPC_CIDR:-10.52.0.0/16}"
SUBNET_CIDR="${SUBNET_CIDR:-10.52.1.0/24}"
STORAGE_INSTANCE_TYPE="${STORAGE_INSTANCE_TYPE:-m4.large}"
CONTROL_INSTANCE_TYPE="${CONTROL_INSTANCE_TYPE:-c6i.xlarge}"
WORKER_INSTANCE_TYPE="${WORKER_INSTANCE_TYPE:-t3.large}"
ROOT_VOL_GB="${ROOT_VOL_GB:-64}"

IDENTITY_FILE="${IDENTITY_FILE:-$HOME/.ssh/2025_06_03.pem}"
KEY_NAME="${KEY_NAME:-$(basename "${IDENTITY_FILE}" .pem)}"

ROLE_NAME="${ROLE_NAME:-${TAG_PREFIX}-node-role}"
INSTANCE_PROFILE_NAME="${INSTANCE_PROFILE_NAME:-${TAG_PREFIX}-node-instance-profile}"

ACCOUNT_ID="${ACCOUNT_ID:-$(aws sts get-caller-identity --query 'Account' --output text)}"
MY_IP="$(curl -s https://checkip.amazonaws.com || true)"
SSH_CIDR="${SSH_CIDR:-${MY_IP:+${MY_IP}/32}}"
SSH_CIDR="${SSH_CIDR:-0.0.0.0/0}"

export AWS_REGION ACCOUNT_ID

[[ -f "${IDENTITY_FILE}" ]] || { echo "Missing IDENTITY_FILE: ${IDENTITY_FILE}"; exit 1; }

case "${BEHAVIOR}" in
  CREATE|REPLACE) ;;
  *)
    echo "Invalid BEHAVIOR=${BEHAVIOR}. Use CREATE or REPLACE."
    exit 1
    ;;
esac

case "${SCHEDULER_MODE}" in
  normal|lambda) ;;
  *)
    echo "Invalid SCHEDULER_MODE=${SCHEDULER_MODE}. Use normal or lambda."
    exit 1
    ;;
esac

echo "== aws_setup =="
echo "Workers:        ${N_WORKERS}"
echo "Behavior:       ${BEHAVIOR}"
echo "Scheduler mode: ${SCHEDULER_MODE}"
echo "K8s version:    ${KUBERNETES_VERSION}"
echo "Region:         ${AWS_REGION}"
echo "Account ID:     ${ACCOUNT_ID}"
echo "AMI:            Ubuntu 24.04 (Noble)"
echo "Key:            ${KEY_NAME} (${IDENTITY_FILE})"
echo "VPC/Subnet:     ${VPC_CIDR} / ${SUBNET_CIDR}"
echo "Out dir:        ${OUT_DIR}"
echo

lookup_tag() {
  local svc_op="$1" key="$2" val="$3" jqexpr="$4"
  # shellcheck disable=SC2086
  aws $svc_op \
    --filters "Name=tag:${key},Values=${val}" \
    --query "$jqexpr" \
    --output text 2>/dev/null || true
}

list_project_instance_ids() {
  aws ec2 describe-instances \
    --filters "Name=tag:Project,Values=${TAG_PREFIX}" \
              "Name=instance-state-name,Values=pending,running,stopping,stopped" \
    --query 'Reservations[].Instances[].InstanceId' \
    --output text 2>/dev/null || true
}

ensure_running() {
  local id="$1"
  local st
  st="$(aws ec2 describe-instances \
    --instance-ids "${id}" \
    --query 'Reservations[0].Instances[0].State.Name' \
    --output text)"
  if [[ "${st}" == "stopped" ]]; then
    aws ec2 start-instances --instance-ids "${id}" >/dev/null
  fi
  aws ec2 wait instance-running --instance-ids "${id}"
}

terminate_project_instances() {
  local ids_txt
  local ids=()

  ids_txt="$(list_project_instance_ids)"
  [[ -z "${ids_txt}" || "${ids_txt}" == "None" ]] && return 0

  read -r -a ids <<<"${ids_txt}"
  [[ ${#ids[@]} -gt 0 ]] || return 0

  echo "[*] Terminating existing ${TAG_PREFIX} deployment: ${ids[*]}"
  aws ec2 terminate-instances --instance-ids "${ids[@]}" >/dev/null
  aws ec2 wait instance-terminated --instance-ids "${ids[@]}"
}

ensure_no_existing_project_instances() {
  local ids_txt
  ids_txt="$(list_project_instance_ids)"
  if [[ -n "${ids_txt}" && "${ids_txt}" != "None" ]]; then
    echo "Existing deployment found for tag prefix ${TAG_PREFIX}: ${ids_txt}"
    echo "Stopped instances still count as an existing deployment."
    echo "Use --behavior replace to roll it over, or terminate the cluster first."
    exit 1
  fi
}

ensure_node_iam() {
  local trust_policy
  local ddb_policy_arn

  trust_policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
  ddb_policy_arn="arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"

  if ! aws iam get-role --role-name "${ROLE_NAME}" >/dev/null 2>&1; then
    echo "[*] Creating IAM role ${ROLE_NAME}"
    aws iam create-role \
      --role-name "${ROLE_NAME}" \
      --assume-role-policy-document "${trust_policy}" >/dev/null

    aws iam attach-role-policy \
      --role-name "${ROLE_NAME}" \
      --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly >/dev/null

    aws iam attach-role-policy \
      --role-name "${ROLE_NAME}" \
      --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess >/dev/null

    aws iam attach-role-policy \
      --role-name "${ROLE_NAME}" \
      --policy-arn "${ddb_policy_arn}" >/dev/null
  else
    echo "[*] Reusing IAM role ${ROLE_NAME}"

    if [[ "$(
      aws iam list-attached-role-policies \
        --role-name "${ROLE_NAME}" \
        --query "AttachedPolicies[?PolicyArn=='${ddb_policy_arn}'] | length(@)" \
        --output text 2>/dev/null || echo 0
    )" == "0" ]]; then
      echo "[*] Attaching DynamoDB policy ${ddb_policy_arn} to existing role ${ROLE_NAME}"
      aws iam attach-role-policy \
        --role-name "${ROLE_NAME}" \
        --policy-arn "${ddb_policy_arn}" >/dev/null
    fi
  fi

  echo "[*] Ensuring inline worker-style IAM policy on role ${ROLE_NAME}"
  aws iam put-role-policy \
    --role-name "${ROLE_NAME}" \
    --policy-name "${ROLE_NAME}-cluster-access" \
    --policy-document "$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:DescribeTable",
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:DeleteItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:BatchGetItem",
        "dynamodb:BatchWriteItem",
        "dynamodb:GetRecords",
        "dynamodb:GetShardIterator",
        "dynamodb:DescribeStream",
        "dynamodb:ListStreams"
      ],
      "Resource": [
        "arn:aws:dynamodb:${AWS_REGION}:${ACCOUNT_ID}:table/*",
        "arn:aws:dynamodb:${AWS_REGION}:${ACCOUNT_ID}:table/*/stream/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket",
        "s3:HeadObject"
      ],
      "Resource": [
        "arn:aws:s3:::ctrlless-mr",
        "arn:aws:s3:::ctrlless-mr/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "ecr:DescribeRepositories",
        "ecr:DescribeImages"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
EOF
)" >/dev/null

  if ! aws iam get-instance-profile --instance-profile-name "${INSTANCE_PROFILE_NAME}" >/dev/null 2>&1; then
    echo "[*] Creating instance profile ${INSTANCE_PROFILE_NAME}"
    aws iam create-instance-profile \
      --instance-profile-name "${INSTANCE_PROFILE_NAME}" >/dev/null
    aws iam add-role-to-instance-profile \
      --instance-profile-name "${INSTANCE_PROFILE_NAME}" \
      --role-name "${ROLE_NAME}" >/dev/null
  else
    echo "[*] Reusing instance profile ${INSTANCE_PROFILE_NAME}"
    if [[ "$(
      aws iam get-instance-profile \
        --instance-profile-name "${INSTANCE_PROFILE_NAME}" \
        --query 'InstanceProfile.Roles[0].RoleName' \
        --output text 2>/dev/null || true
    )" != "${ROLE_NAME}" ]]; then
      local role_in_profile
      role_in_profile="$(aws iam get-instance-profile \
        --instance-profile-name "${INSTANCE_PROFILE_NAME}" \
        --query 'InstanceProfile.Roles[0].RoleName' \
        --output text 2>/dev/null || true)"
      if [[ -n "${role_in_profile}" && "${role_in_profile}" != "None" ]]; then
        aws iam remove-role-from-instance-profile \
          --instance-profile-name "${INSTANCE_PROFILE_NAME}" \
          --role-name "${role_in_profile}" >/dev/null || true
      fi
      aws iam add-role-to-instance-profile \
        --instance-profile-name "${INSTANCE_PROFILE_NAME}" \
        --role-name "${ROLE_NAME}" >/dev/null
    fi
  fi

  echo "[*] Waiting for instance profile ${INSTANCE_PROFILE_NAME} to be ready"
  local max_wait=30
  local elapsed=0
  local delay=1
  while [[ ${elapsed} -lt ${max_wait} ]]; do
    if aws iam get-instance-profile --instance-profile-name "${INSTANCE_PROFILE_NAME}" >/dev/null 2>&1; then
      echo "[+] Instance profile ${INSTANCE_PROFILE_NAME} is now available"
      return 0
    fi
    sleep "${delay}"
    elapsed=$((elapsed + delay))
    if (( delay < 8 )); then
      delay=$((delay * 2))
    fi
  done

  echo "Timeout waiting for instance profile ${INSTANCE_PROFILE_NAME}"
  exit 1
}

emit_env() {
  printf 'export %s=%q\n' "$1" "$2"
}

if ! aws ec2 describe-key-pairs --key-names "${KEY_NAME}" >/dev/null 2>&1; then
  echo "[*] Importing EC2 key pair ${KEY_NAME}"
  aws ec2 import-key-pair \
    --key-name "${KEY_NAME}" \
    --public-key-material "$(ssh-keygen -y -f "${IDENTITY_FILE}")" >/dev/null
fi

AMI_ID="$(
  aws ssm get-parameters \
    --names "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id" \
    --query 'Parameters[0].Value' \
    --output text 2>/dev/null || true
)"
if [[ -z "${AMI_ID}" || "${AMI_ID}" == "None" ]]; then
  AMI_ID="$(
    aws ec2 describe-images \
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
[[ -n "${AMI_ID}" && "${AMI_ID}" != "None" ]] || { echo "No Ubuntu 24.04 AMI found"; exit 1; }

ensure_node_iam

case "${BEHAVIOR}" in
  REPLACE) terminate_project_instances ;;
  CREATE) ensure_no_existing_project_instances ;;
esac

VPC_ID="$(lookup_tag 'ec2 describe-vpcs' 'Name' "${TAG_PREFIX}-vpc" 'Vpcs[0].VpcId')"
if [[ -z "${VPC_ID}" || "${VPC_ID}" == "None" ]]; then
  VPC_ID="$(aws ec2 create-vpc --cidr-block "${VPC_CIDR}" --query 'Vpc.VpcId' --output text)"
  aws ec2 create-tags --resources "${VPC_ID}" --tags "Key=Name,Value=${TAG_PREFIX}-vpc"
  aws ec2 modify-vpc-attribute --vpc-id "${VPC_ID}" --enable-dns-hostnames
fi

IGW_ID="$(lookup_tag 'ec2 describe-internet-gateways' 'Name' "${TAG_PREFIX}-igw" 'InternetGateways[0].InternetGatewayId')"
if [[ -z "${IGW_ID}" || "${IGW_ID}" == "None" ]]; then
  IGW_ID="$(aws ec2 create-internet-gateway --query 'InternetGateway.InternetGatewayId' --output text)"
  aws ec2 create-tags --resources "${IGW_ID}" --tags "Key=Name,Value=${TAG_PREFIX}-igw"
  aws ec2 attach-internet-gateway --internet-gateway-id "${IGW_ID}" --vpc-id "${VPC_ID}"
fi

RT_ID="$(lookup_tag 'ec2 describe-route-tables' 'Name' "${TAG_PREFIX}-rt" 'RouteTables[0].RouteTableId')"
if [[ -z "${RT_ID}" || "${RT_ID}" == "None" ]]; then
  RT_ID="$(aws ec2 create-route-table --vpc-id "${VPC_ID}" --query 'RouteTable.RouteTableId' --output text)"
  aws ec2 create-tags --resources "${RT_ID}" --tags "Key=Name,Value=${TAG_PREFIX}-rt"
  aws ec2 create-route \
    --route-table-id "${RT_ID}" \
    --destination-cidr-block 0.0.0.0/0 \
    --gateway-id "${IGW_ID}" >/dev/null
fi

SUBNET_ID="$(lookup_tag 'ec2 describe-subnets' 'Name' "${TAG_PREFIX}-subnet" 'Subnets[0].SubnetId')"
if [[ -z "${SUBNET_ID}" || "${SUBNET_ID}" == "None" ]]; then
  AZ="$(
    aws ec2 describe-availability-zones \
      --region "${AWS_REGION}" \
      --query 'AvailabilityZones[?State==`available`].ZoneName | [0]' \
      --output text
  )"
  SUBNET_ID="$(
    aws ec2 create-subnet \
      --vpc-id "${VPC_ID}" \
      --cidr-block "${SUBNET_CIDR}" \
      --availability-zone "${AZ}" \
      --query 'Subnet.SubnetId' \
      --output text
  )"
  aws ec2 create-tags --resources "${SUBNET_ID}" --tags "Key=Name,Value=${TAG_PREFIX}-subnet"
  aws ec2 modify-subnet-attribute --subnet-id "${SUBNET_ID}" --map-public-ip-on-launch
  aws ec2 associate-route-table --route-table-id "${RT_ID}" --subnet-id "${SUBNET_ID}" >/dev/null
fi

if [[ "$(
  aws ec2 describe-subnets \
    --subnet-ids "${SUBNET_ID}" \
    --query 'Subnets[0].MapPublicIpOnLaunch' \
    --output text
)" != "True" ]]; then
  aws ec2 modify-subnet-attribute --subnet-id "${SUBNET_ID}" --map-public-ip-on-launch
fi

CUR_RT="$(aws ec2 describe-route-tables \
  --filters "Name=association.subnet-id,Values=${SUBNET_ID}" \
  --query 'RouteTables[0].RouteTableId' --output text 2>/dev/null || true)"
if [[ -z "${CUR_RT}" || "${CUR_RT}" == "None" || "${CUR_RT}" != "${RT_ID}" ]]; then
  ASSOC_ID="$(aws ec2 describe-route-tables \
    --filters "Name=association.subnet-id,Values=${SUBNET_ID}" \
    --query 'RouteTables[0].Associations[0].RouteTableAssociationId' --output text 2>/dev/null || true)"
  if [[ -n "${ASSOC_ID}" && "${ASSOC_ID}" != "None" ]]; then
    aws ec2 replace-route-table-association \
      --association-id "${ASSOC_ID}" \
      --route-table-id "${RT_ID}" >/dev/null
  else
    aws ec2 associate-route-table \
      --route-table-id "${RT_ID}" \
      --subnet-id "${SUBNET_ID}" >/dev/null
  fi
fi

SG_ID="$(lookup_tag 'ec2 describe-security-groups' 'Name' "${TAG_PREFIX}-sg" 'SecurityGroups[0].GroupId')"
if [[ -z "${SG_ID}" || "${SG_ID}" == "None" ]]; then
  SG_ID="$(aws ec2 create-security-group \
    --group-name "${TAG_PREFIX}-sg" \
    --description "${TAG_PREFIX} sg" \
    --vpc-id "${VPC_ID}" \
    --query 'GroupId' \
    --output text)"
  aws ec2 create-tags --resources "${SG_ID}" --tags "Key=Name,Value=${TAG_PREFIX}-sg"
fi

ensure_self_ingress() {
  local have_rule
  have_rule="$(
    aws ec2 describe-security-groups \
      --group-ids "${SG_ID}" \
      --query "SecurityGroups[0].IpPermissions[?UserIdGroupPairs[?GroupId=='${SG_ID}']] | length(@)" \
      --output text 2>/dev/null || echo 0
  )"
  if [[ "${have_rule}" == "0" ]]; then
    aws ec2 authorize-security-group-ingress \
      --group-id "${SG_ID}" \
      --protocol -1 \
      --source-group "${SG_ID}" >/dev/null
  fi
}

sync_cidr_port() {
  local port="$1"
  local cidr="$2"

  local existing
  existing="$(
    aws ec2 describe-security-groups \
      --group-ids "${SG_ID}" \
      --query "SecurityGroups[0].IpPermissions[?FromPort==\`${port}\` && ToPort==\`${port}\` && IpProtocol=='tcp'].IpRanges[].CidrIp" \
      --output text 2>/dev/null || true
  )"

  for old_cidr in ${existing}; do
    if [[ "${old_cidr}" != "${cidr}" ]]; then
      aws ec2 revoke-security-group-ingress \
        --group-id "${SG_ID}" \
        --protocol tcp \
        --port "${port}" \
        --cidr "${old_cidr}" >/dev/null 2>&1 || true
    fi
  done

  aws ec2 authorize-security-group-ingress \
    --group-id "${SG_ID}" \
    --protocol tcp \
    --port "${port}" \
    --cidr "${cidr}" >/dev/null 2>&1 || true
}

find_vpc_endpoint_id() {
  local service_name="$1"

  aws ec2 describe-vpc-endpoints \
    --filters "Name=vpc-id,Values=${VPC_ID}" \
              "Name=service-name,Values=${service_name}" \
    --query "VpcEndpoints[?State!='deleted' && State!='deleting'] | [0].VpcEndpointId" \
    --output text 2>/dev/null || true
}

wait_for_vpc_endpoint() {
  local endpoint_id="$1"
  local max_wait="${2:-120}"
  local elapsed=0
  local delay=2
  local state=""

  while [[ ${elapsed} -lt ${max_wait} ]]; do
    state="$(
      aws ec2 describe-vpc-endpoints \
        --vpc-endpoint-ids "${endpoint_id}" \
        --query 'VpcEndpoints[0].State' \
        --output text 2>/dev/null || true
    )"

    case "${state}" in
      available)
        return 0
        ;;
      pending|pendingAcceptance|"")
        sleep "${delay}"
        elapsed=$((elapsed + delay))
        ;;
      failed|rejected|expired)
        echo "VPC endpoint ${endpoint_id} entered terminal state: ${state}"
        return 1
        ;;
      *)
        sleep "${delay}"
        elapsed=$((elapsed + delay))
        ;;
    esac
  done

  echo "Timed out waiting for VPC endpoint ${endpoint_id} to become available (last state: ${state:-unknown})"
  return 1
}

ensure_gateway_vpc_endpoint() {
  local service_short_name="$1"
  local name_tag="$2"
  local service_name endpoint_id

  service_name="com.amazonaws.${AWS_REGION}.${service_short_name}"
  endpoint_id="$(find_vpc_endpoint_id "${service_name}")"

  if [[ -z "${endpoint_id}" || "${endpoint_id}" == "None" ]]; then
    echo "[*] Creating ${service_short_name} gateway VPC endpoint"
    endpoint_id="$(
      aws ec2 create-vpc-endpoint \
        --vpc-id "${VPC_ID}" \
        --service-name "${service_name}" \
        --route-table-ids "${RT_ID}" \
        --tag-specifications "ResourceType=vpc-endpoint,Tags=[{Key=Name,Value=${name_tag}},{Key=Project,Value=${TAG_PREFIX}}]" \
        --query 'VpcEndpoint.VpcEndpointId' \
        --output text
    )"
  else
    echo "[*] Reusing ${service_short_name} gateway VPC endpoint ${endpoint_id}"
  fi

  wait_for_vpc_endpoint "${endpoint_id}"
}

ensure_interface_vpc_endpoint() {
  local service_short_name="$1"
  local name_tag="$2"
  local service_name endpoint_id

  service_name="com.amazonaws.${AWS_REGION}.${service_short_name}"
  endpoint_id="$(find_vpc_endpoint_id "${service_name}")"

  if [[ -z "${endpoint_id}" || "${endpoint_id}" == "None" ]]; then
    echo "[*] Creating ${service_short_name} interface VPC endpoint"
    endpoint_id="$(
      aws ec2 create-vpc-endpoint \
        --vpc-endpoint-type Interface \
        --vpc-id "${VPC_ID}" \
        --service-name "${service_name}" \
        --private-dns-enabled \
        --subnet-ids "${SUBNET_ID}" \
        --security-group-ids "${SG_ID}" \
        --tag-specifications "ResourceType=vpc-endpoint,Tags=[{Key=Name,Value=${name_tag}},{Key=Project,Value=${TAG_PREFIX}}]" \
        --query 'VpcEndpoint.VpcEndpointId' \
        --output text
    )"
  else
    echo "[*] Reusing ${service_short_name} interface VPC endpoint ${endpoint_id}"
  fi

  wait_for_vpc_endpoint "${endpoint_id}"
}

ensure_self_ingress
sync_cidr_port 22 "${SSH_CIDR}"
sync_cidr_port 6443 "${SSH_CIDR}"

if [[ "${SCHEDULER_MODE}" == "lambda" ]]; then
  echo "[*] Ensuring Lambda scheduler VPC endpoints"
  ensure_gateway_vpc_endpoint dynamodb "${TAG_PREFIX}-vpce-dynamodb"
  ensure_interface_vpc_endpoint sqs "${TAG_PREFIX}-vpce-sqs"
  ensure_interface_vpc_endpoint lambda "${TAG_PREFIX}-vpce-lambda"
  ensure_interface_vpc_endpoint execute-api "${TAG_PREFIX}-vpce-execute-api"
  ensure_interface_vpc_endpoint ssm "${TAG_PREFIX}-vpce-ssm"
fi

run_inst() {
  local name="$1" instance_type="$2"
  aws ec2 run-instances \
    --image-id "${AMI_ID}" \
    --instance-type "${instance_type}" \
    --key-name "${KEY_NAME}" \
    --subnet-id "${SUBNET_ID}" \
    --security-group-ids "${SG_ID}" \
    --associate-public-ip-address \
    --iam-instance-profile Name="${INSTANCE_PROFILE_NAME}" \
    --block-device-mappings "[{\"DeviceName\":\"/dev/sda1\",\"Ebs\":{\"DeleteOnTermination\":true,\"VolumeSize\":${ROOT_VOL_GB},\"VolumeType\":\"gp3\"}}]" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${name}},{Key=Project,Value=${TAG_PREFIX}}]" \
    --query 'Instances[0].InstanceId' \
    --output text
}

echo "[*] Launching instances:"
echo "    storage: ${STORAGE_INSTANCE_TYPE}, control: ${CONTROL_INSTANCE_TYPE}, workers: ${WORKER_INSTANCE_TYPE}, root ${ROOT_VOL_GB}GB"

ID_STORAGE="$(run_inst "${K8S_CLUSTER_NAME}-storage" "${STORAGE_INSTANCE_TYPE}")"
ID_CONTROL="$(run_inst "${K8S_CLUSTER_NAME}-control" "${CONTROL_INSTANCE_TYPE}")"
declare -a WORKER_IDS=()
for i in $(seq 1 "${N_WORKERS}"); do
  WORKER_IDS+=("$(run_inst "$(printf "%s-worker-%02d" "${K8S_CLUSTER_NAME}" "$i")" "${WORKER_INSTANCE_TYPE}")")
done

: "${ID_STORAGE:?failed to create storage instance}"
: "${ID_CONTROL:?failed to create control instance}"

IDS=("${ID_STORAGE}" "${ID_CONTROL}")
if ((${#WORKER_IDS[@]} > 0)); then
  IDS+=("${WORKER_IDS[@]}")
fi

aws ec2 wait instance-status-ok --instance-ids "${IDS[@]}"

desc_json="$(aws ec2 describe-instances --instance-ids "${IDS[@]}")"
priv_ip(){ echo "${desc_json}" | jq -r ".Reservations[].Instances[] | select(.InstanceId==\"$1\").PrivateIpAddress"; }
pub_ip(){ echo "${desc_json}" | jq -r ".Reservations[].Instances[] | select(.InstanceId==\"$1\").PublicIpAddress"; }

STORAGE_PRIV="$(priv_ip "${ID_STORAGE}")"
STORAGE_PUB="$(pub_ip "${ID_STORAGE}")"
CONTROL_PRIV="$(priv_ip "${ID_CONTROL}")"
CONTROL_PUB="$(pub_ip "${ID_CONTROL}")"

declare -a WORKER_PRIVS=() WORKER_PUBS=()
for id in "${WORKER_IDS[@]}"; do
  WORKER_PRIVS+=("$(priv_ip "${id}")")
  WORKER_PUBS+=("$(pub_ip "${id}")")
done

mkdir -p "${OUT_DIR}"
ENV_FILE="${OUT_DIR}/cluster.env"
{
  emit_env AWS_REGION "${AWS_REGION}"
  emit_env ACCOUNT_ID "${ACCOUNT_ID}"
  emit_env TAG_PREFIX "${TAG_PREFIX}"
  emit_env K8S_CLUSTER_NAME "${K8S_CLUSTER_NAME}"
  emit_env LAMBDA_RESOURCE_PREFIX "${LAMBDA_RESOURCE_PREFIX}"
  emit_env LAMBDA_KUBECONFIG_PARAMETER_PREFIX "${LAMBDA_KUBECONFIG_PARAMETER_PREFIX}"
  emit_env BEHAVIOR "${BEHAVIOR}"
  emit_env SCHEDULER_MODE "${SCHEDULER_MODE}"
  emit_env KUBERNETES_VERSION "${KUBERNETES_VERSION}"
  emit_env PODGC_CONTROLLER_NAME "${PODGC_CONTROLLER_NAME}"
  emit_env POD_CIDR "${POD_CIDR}"
  emit_env SERVICE_CIDR "${SERVICE_CIDR}"
  emit_env CNI_MANIFEST_URL "${CNI_MANIFEST_URL}"
  emit_env CNI_PLUGINS_VERSION "${CNI_PLUGINS_VERSION}"
  emit_env REPO_LOCAL_DIR "${REPO_LOCAL_DIR}"
  emit_env K8S_DIR "${K8S_DIR:-${REPO_LOCAL_DIR}/kubernetes}"
  emit_env OUT_DIR "${OUT_DIR}"
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
  emit_env SSH_CIDR "${SSH_CIDR}"
  emit_env N_WORKERS "${N_WORKERS}"
  emit_env ID_STORAGE "${ID_STORAGE}"
  emit_env ID_CONTROL "${ID_CONTROL}"
  emit_env STORAGE_PRIV "${STORAGE_PRIV}"
  emit_env STORAGE_PUB "${STORAGE_PUB}"
  emit_env CONTROL_PRIV "${CONTROL_PRIV}"
  emit_env CONTROL_PUB "${CONTROL_PUB}"
  emit_env WORKER_IDS "${WORKER_IDS[*]}"
  idx=1
  for ((i=0; i<${#WORKER_IDS[@]}; i++)); do
    printf 'export WORKER%02d_ID=%q\n' "$idx" "${WORKER_IDS[$i]}"
    printf 'export WORKER%02d_PRIV=%q\n' "$idx" "${WORKER_PRIVS[$i]}"
    printf 'export WORKER%02d_PUB=%q\n' "$idx" "${WORKER_PUBS[$i]}"
    idx=$((idx + 1))
  done
} > "${ENV_FILE}"

echo
echo "Wrote ${ENV_FILE}"
echo "  storage: ${STORAGE_PRIV} (pub ${STORAGE_PUB})"
echo "  control: ${CONTROL_PRIV} (pub ${CONTROL_PUB})"
idx=1
for ((i=0; i<${#WORKER_IDS[@]}; i++)); do
  printf "  worker-%02d: %s (pub %s)\n" "$idx" "${WORKER_PRIVS[$i]}" "${WORKER_PUBS[$i]}"
  idx=$((idx + 1))
done
