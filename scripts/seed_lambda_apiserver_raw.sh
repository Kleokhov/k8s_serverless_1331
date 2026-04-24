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

while [[ $# -gt 0 ]]; do
  case "$1" in
    --kubeconfig) KUBECONFIG_PATH="$2"; shift 2 ;;
    --namespaces) NAMESPACES="$2"; shift 2 ;;
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
  local attempt
  local max_attempts="${API_REQUEST_MAX_ATTEMPTS:-6}"
  local delay=2

  printf '%s' "${payload}" > "${request_body_file}"

  for ((attempt=1; attempt<=max_attempts; attempt++)); do
    code="$(
      curl -sS -k \
        -o "${response_body_file}" \
        -w '%{http_code}' \
        -X "${method}" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: ${content_type}" \
        --data-binary @"${request_body_file}" \
        "${server}${path}"
    )" || code="000"

    case "${code}" in
      200|201)
        echo "  ensured ${label}"
        return 0
        ;;
      409)
        echo "  exists  ${label}"
        return 0
        ;;
      403|429|500|502|503|504|000)
        if (( attempt < max_attempts )); then
          echo "  retry ${attempt}/${max_attempts} ${label}: HTTP ${code} (likely transient API Gateway/Lambda warmup)"
          sleep "${delay}"
          delay=$(( delay * 2 ))
          continue
        fi
        ;;
    esac

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
  done
}

seed_namespace() {
  local name="$1"
  local payload
  payload="$(printf '{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"%s"}}' "${name}")"
  api_request POST "/api/v1/namespaces" "application/json" "${payload}" "namespace/${name}"
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
