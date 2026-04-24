#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/seed_lambda_apiserver_raw.sh --kubeconfig PATH [options]

Seeds fixed Kubernetes resources through concrete REST endpoints. This avoids
kubectl discovery/OpenAPI calls, which are not reliable in the handler-only
Lambda apiserver MVP.

Options:
  --kubeconfig PATH       Kubeconfig containing server and bearer token.
  --namespaces LIST       Comma-separated namespaces to create.
  --synthetic-nodes N     Number of synthetic Nodes to create (default: 0).
  --node-prefix PREFIX    Synthetic node prefix (default: serverless-node).
  -h, --help              Show help.
EOF
}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1"
    exit 1
  }
}

KUBECONFIG_PATH=""
NAMESPACES="default,kube-system,kube-public,kube-node-lease"
SYNTHETIC_NODES=0
NODE_PREFIX="serverless-node"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --kubeconfig) KUBECONFIG_PATH="$2"; shift 2 ;;
    --namespaces) NAMESPACES="$2"; shift 2 ;;
    --synthetic-nodes) SYNTHETIC_NODES="$2"; shift 2 ;;
    --node-prefix) NODE_PREFIX="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

need curl

[[ -n "${KUBECONFIG_PATH}" && -f "${KUBECONFIG_PATH}" ]] || {
  echo "Missing kubeconfig. Use --kubeconfig PATH."
  exit 1
}

server="$(awk '$1 == "server:" {print $2; exit}' "${KUBECONFIG_PATH}" | tr -d '\r')"
token="$(awk '$1 == "token:" {print $2; exit}' "${KUBECONFIG_PATH}" | tr -d '\r')"

[[ -n "${server}" ]] || { echo "Failed to read cluster server from ${KUBECONFIG_PATH}"; exit 1; }
[[ -n "${token}" ]] || { echo "Failed to read bearer token from ${KUBECONFIG_PATH}"; exit 1; }

server="${server%/}"

request_body_file="$(mktemp)"
response_body_file="$(mktemp)"
trap 'rm -f "${request_body_file}" "${response_body_file}"' EXIT

api_request() {
  local method="$1"
  local path="$2"
  local content_type="$3"
  local payload="$4"
  local label="$5"
  local code

  printf '%s' "${payload}" > "${request_body_file}"
  code="$(
    curl -sS -k \
      -o "${response_body_file}" \
      -w '%{http_code}' \
      -X "${method}" \
      -H "Authorization: Bearer ${token}" \
      -H "Content-Type: ${content_type}" \
      --data-binary @"${request_body_file}" \
      "${server}${path}"
  )"

  case "${code}" in
    200|201)
      echo "  ensured ${label}"
      ;;
    409)
      echo "  exists  ${label}"
      ;;
    *)
      echo "Failed to ${method} ${label} at ${path}: HTTP ${code}"
      sed -n '1,80p' "${response_body_file}"
      if [[ "${code}" == "502" ]]; then
        cat <<'EOF'
HTTP 502 means API Gateway could not get a valid response from the Lambda
apiserver. Check CloudWatch logs for the Lambda function; after changing
lambda/cmd/apiserver or lambda/pkg/apiserver, redeploy the apiserver image
before retrying seed-only.
EOF
      fi
      return 1
      ;;
  esac
}

seed_namespace() {
  local name="$1"
  local payload
  payload="$(printf '{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"%s"}}' "${name}")"
  api_request POST "/api/v1/namespaces" "application/json" "${payload}" "namespace/${name}"
}

seed_synthetic_node() {
  local name="$1"
  local create_payload status_payload
  create_payload="$(cat <<EOF
{
  "apiVersion": "v1",
  "kind": "Node",
  "metadata": {
    "name": "${name}",
    "labels": {
      "kubernetes.io/hostname": "${name}",
      "kubernetes.io/os": "linux",
      "kubernetes.io/arch": "amd64",
      "node.kubernetes.io/instance-type": "lambda-synthetic"
    }
  },
  "spec": {}
}
EOF
)"
  api_request POST "/api/v1/nodes" "application/json" "${create_payload}" "node/${name}"

  status_payload="$(cat <<EOF
{
  "status": {
    "capacity": {
      "cpu": "4",
      "memory": "16Gi",
      "pods": "110"
    },
    "allocatable": {
      "cpu": "4",
      "memory": "16Gi",
      "pods": "110"
    },
    "conditions": [
      {
        "type": "Ready",
        "status": "True",
        "reason": "SyntheticNodeReady",
        "message": "Synthetic node seeded for Lambda scheduler experiments"
      }
    ],
    "nodeInfo": {
      "architecture": "amd64",
      "operatingSystem": "linux",
      "kubeletVersion": "v1.33.1",
      "containerRuntimeVersion": "containerd://synthetic",
      "kernelVersion": "synthetic",
      "osImage": "synthetic"
    }
  }
}
EOF
)"
  api_request PATCH "/api/v1/nodes/${name}/status" "application/strategic-merge-patch+json" "${status_payload}" "node/${name}/status"
}

if [[ -n "${NAMESPACES}" ]]; then
  echo "[*] Seeding namespaces via raw REST"
  IFS=',' read -r -a namespace_items <<<"${NAMESPACES}"
  for namespace in "${namespace_items[@]}"; do
    namespace="${namespace//[[:space:]]/}"
    [[ -n "${namespace}" ]] || continue
    seed_namespace "${namespace}"
  done
fi

if [[ "${SYNTHETIC_NODES}" != "0" ]]; then
  echo "[*] Seeding ${SYNTHETIC_NODES} synthetic node(s) via raw REST"
  for i in $(seq 1 "${SYNTHETIC_NODES}"); do
    seed_synthetic_node "$(printf '%s-%02d' "${NODE_PREFIX}" "${i}")"
  done
fi
