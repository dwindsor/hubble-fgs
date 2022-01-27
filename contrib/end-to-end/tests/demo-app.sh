#!/bin/bash

set -xeu

CLUSTER_NAME="fgs-cli-ci"
PROJECT_ROOT="$(realpath $(dirname "${BASH_SOURCE[0]}")/../../..)"
cd "$PROJECT_ROOT"

if ! command -v kind; then
    echo "kind is not in \$PATH... Bailing out!" 1>&2
    exit -1
fi

if ! kind get clusters | grep "$CLUSTER_NAME" &>/dev/null; then
    echo "Cluster \"$CLUSTER_NAME\" does not exist! Bailing out!" 1>&2
    exit -1
fi

kubectl cluster-info --context "kind-$CLUSTER_NAME"

echo "Applying tracing policies..." 1>&2
kubectl apply -f crds/isovalent.com_tracingpolicies.yaml --wait
sleep 5 # FIXME: why is waiting above not enough?
kubectl apply -f crds/examples/tls.yaml --wait

echo "Deploying demo app..." 1>&2
kubectl create namespace tenant-jobs || true
kubectl -n tenant-jobs apply -f https://docs.isovalent.com/public/jobs-app-attack.yaml
echo "Waiting for demo app to be ready..." 1>&2
kubectl wait -n tenant-jobs --for=condition=Ready --all pod --timeout=5m

echo "Running workload..." 1>&2
kubectl exec -n tenant-jobs deployment/jobposting -- curl localhost:9080 -m 1 || true
kubectl exec -n tenant-jobs deployment/jobposting -- curl -4 https://google.com -m 30
echo "Sleeping for 60 seconds..." 1>&2
sleep 60

contrib/end-to-end/dump-fgs-logs.sh
go run ./tests/jobs.trace.go contrib/end-to-end/logs/fgs.json
