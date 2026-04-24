#!/usr/bin/env bash
set -euo pipefail

CTX="${CTX:-kind-local-apiserver}"
NS="crudtest-$(date +%s)"

echo "==> Create namespace"
kubectl --context "$CTX" create namespace "$NS"

echo "==> Create configmap"
kubectl --context "$CTX" -n "$NS" create configmap cm1 --from-literal=a=1

echo "==> Get (read back)"
kubectl --context "$CTX" -n "$NS" get configmap cm1 -o yaml

echo "==> Patch (merge patch)"
kubectl --context "$CTX" -n "$NS" patch configmap cm1 --type merge -p '{"data":{"a":"2","b":"x"}}'
kubectl --context "$CTX" -n "$NS" get configmap cm1 -o jsonpath='{.data.a}{" "}{.data.b}{"\n"}'

echo "==> Update (PUT via replace)"
kubectl --context "$CTX" -n "$NS" get configmap cm1 -o json \
  | jq '.data.c="3"' \
  | kubectl --context "$CTX" replace -f -

kubectl --context "$CTX" -n "$NS" get configmap cm1 -o jsonpath='{.data.c}{"\n"}'

echo "==> List"
kubectl --context "$CTX" -n "$NS" get configmaps

echo "==> Delete configmap"
kubectl --context "$CTX" -n "$NS" delete configmap cm1

echo "==> Delete namespace"
kubectl --context "$CTX" delete namespace "$NS"

echo "OK"