#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$SCRIPT_DIR"

APISERVER_DIR="${APISERVER_DIR:-$REPO_ROOT/apiserver}"
DYNAMO_REGION="${DYNAMO_REGION:-us-east-1}"
DYNAMO_TABLE="${DYNAMO_TABLE:-dynamo}"

if [[ ! -d "$APISERVER_DIR" ]]; then
  echo "ERROR: apiserver dir not found: $APISERVER_DIR"
  exit 1
fi

cd "$APISERVER_DIR"

echo "==> Precreating DynamoDB tables"
echo "    apiserver dir: $APISERVER_DIR"
echo "    region:        $DYNAMO_REGION"
echo "    table base:    $DYNAMO_TABLE"

GOFLAGS="-buildvcs=false -mod=mod" \
  go run ./tools/init-dynamo-tables \
    --region "$DYNAMO_REGION" \
    --table "$DYNAMO_TABLE"