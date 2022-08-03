#!/bin/bash

set -eu -o pipefail

CLUSTER_NAME="fgs-cli-ci"
PROJECT_ROOT="$(realpath $(dirname "${BASH_SOURCE[0]}")/../../..)"
SCRIPTDIR="$(realpath $(dirname "${BASH_SOURCE[0]}")/..)"
source "$SCRIPTDIR/tests/helpers"
mkdir -p $SCRIPTDIR/logs
cd "$PROJECT_ROOT"

export PATH="$PATH:/usr/local/go/bin"
KERNEL_VERSION=$(kubectl get node -o go-template='{{(index .items 0).status.nodeInfo.kernelVersion}}')

echo "Waiting for FGS pods to be ready..." 1>&2
for i in $(seq 10); do
    kubectl rollout status ds/hubble-enterprise -n kube-system --timeout=30s && break || sleep 10
done
if [ $? -ne 0 ]; then
    echo "Failed to wait for FGS..." 1>&2
    exit 1
fi

echo "Forwarding gRPC ports..." 1>&2
forward_grpc
SERVER_ARGS=()
for port in ${GRPC_PORTS[@]}; do
    SERVER_ARGS+=("--server-address" "localhost:$port")
done

kubectl apply -f crds/examples/tls.yaml
echo "Waiting to make sure sensors have been loaded..." 1>&2
sleep 30 # Wait 30 seconds for now to make sure sensors have had a chance to load

echo "Deploying curl pod..." 1>&2
kubectl apply -f contrib/end-to-end/yaml/http-tls-end-to-end.yaml

echo "Waiting for curl pod to be ready..." 1>&2
for i in $(seq 10); do
    kubectl wait -n curl --for=condition=Ready --all pod --timeout=30s && break || sleep 10
done
if [ $? -ne 0 ]; then
    echo "Failed to wait for curl pod..." 1>&2
    exit 1
fi

echo "Checking HTTP events..." 1>&2
go run ./cmd/checkerpc check crds/eventchecker/tests/http.yaml --events 20000 ${SERVER_ARGS[@]} --kernel "$KERNEL_VERSION" 2>&1 | tee $SCRIPTDIR/logs/checker-http.log &
HTTP_CHECKER_PID=$!
sleep 30
kubectl exec -n curl deployment/curl -- curl -4 http://google.com -m 30
wait $HTTP_CHECKER_PID

echo "Checking TLS events..." 1>&2
go run ./cmd/checkerpc check crds/eventchecker/tests/tls.yaml --events 20000 ${SERVER_ARGS[@]} --kernel "$KERNEL_VERSION" 2>&1 | tee $SCRIPTDIR/logs/checker-tls.log &
TLS_CHECKER_PID=$!
sleep 30
kubectl exec -n curl deployment/curl -- curl -4 https://google.com -m 30
wait $TLS_CHECKER_PID
