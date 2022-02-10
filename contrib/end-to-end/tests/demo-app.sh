#!/bin/bash

set -xeu

CLUSTER_NAME="fgs-cli-ci"
PROJECT_ROOT="$(realpath $(dirname "${BASH_SOURCE[0]}")/../../..)"
cd "$PROJECT_ROOT"

export PATH="$PATH:/usr/local/go/bin"

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
kubectl apply -f crds/isovalent.com_tracingpolicies.yaml
sleep 5 # Wait so that we can give a change for the new CRD to be applied
kubectl apply -f crds/examples/tls.yaml
echo "Waiting to make sure sensors have been loaded..." 1>&2
sleep 30 # Wait 30 seconds for now to make sure sensors have had a chance to load

echo "Deploying curl pod..." 1>&2
kubectl apply -f contrib/end-to-end/yaml/http-tls-end-to-end.yaml

echo "Waiting for curl pod to be ready..." 1>&2
for i in $(seq 3); do
    kubectl wait -n curl --for=condition=Ready --all pod --timeout=5m && break || sleep 30
done
if [ $? -ne 0 ]; then
    echo "Failed to wait for curl pod..." 1>&2
    exit 1
fi

echo "Generating curl http and tls events..." 1>&2
kubectl exec -n curl deployment/curl -- curl -4 https://google.com -m 30
kubectl exec -n curl deployment/curl -- curl -4 http://google.com -m 30

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

echo "Running workload. Sleeping for 60 seconds..." 1>&2
kubectl exec -n tenant-jobs deployment/jobposting -- curl localhost:9080 -m 15 || true
sleep 60

contrib/end-to-end/dump-fgs-logs.sh
go run ./tests/jobs.trace.go contrib/end-to-end/logs/fgs.json
