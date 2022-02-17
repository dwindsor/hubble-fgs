#!/bin/bash

set -eu

CLUSTER_NAME="fgs-cli-ci"
PROJECT_ROOT="$(realpath $(dirname "${BASH_SOURCE[0]}")/../../..)"
SCRIPTDIR="$(realpath $(dirname "${BASH_SOURCE[0]}")/..)"
source "$SCRIPTDIR/tests/helpers"
mkdir -p $SCRIPTDIR/logs
cd "$PROJECT_ROOT"

usage() {
    echo "usage: $0 [--no-tracingpolicy]" 1>&2
    echo "    --no-tracingpolicy  don't load a tracing policy" 1>&2
}

TRACINGPOLICY=1

while [ $# -ge 1 ]; do
    if [ "$1" == "--no-tracingpolicy" ]; then
        TRACINGPOLICY=0
        shift
    else
        usage
    fi
done

export PATH="$PATH:/usr/local/go/bin"
KERNEL_VERSION=$(kubectl get node -o go-template='{{(index .items 0).status.nodeInfo.kernelVersion}}')

echo "Forwarding gRPC ports..." 1>&2
forward_grpc
SERVER_ARGS=()
for port in ${GRPC_PORTS[@]}; do
    SERVER_ARGS+=("--server-address" "localhost:$port")
done

if [ $TRACINGPOLICY == 1 ]; then
    echo "Applying tracing policies..." 1>&2
    kubectl apply -f crds/isovalent.com_tracingpolicies.yaml
    sleep 5 # Wait so that we can give a chance for the new CRD to be applied
    kubectl apply -f crds/examples/tls.yaml
    echo "Waiting to make sure sensors have been loaded..." 1>&2
    sleep 30 # Wait 30 seconds for now to make sure sensors have had a chance to load
fi

echo "Checking demo app events..." 1>&2
go run ./cmd/checkerpc --events 20000 --timeout 1200 --check demo-app ${SERVER_ARGS[@]} --kernel "$KERNEL_VERSION" 2>&1 | tee $SCRIPTDIR/logs/checker-demo-app.log &
DEMO_APP_CHECKER_PID=$!
# Wait long enough for every client to either connect or timeout
sleep 10

echo "Deploying demo app..." 1>&2
kubectl delete namespace tenant-jobs || true
kubectl create namespace tenant-jobs
kubectl -n tenant-jobs apply -f https://docs.isovalent.com/public/jobs-app-attack.yaml

echo "Waiting for demo app to be ready..." 1>&2
for i in $(seq 3); do
    kubectl wait -n tenant-jobs --for=condition=Ready --all pod --timeout=5m && break || sleep 30
done
if [ $? -ne 0 ]; then
    echo "Failed to wait for demo app..." 1>&2
    exit 1
fi
kubectl exec -n tenant-jobs deployment/jobposting -- curl localhost:9080 -m 15 || true

wait $DEMO_APP_CHECKER_PID
