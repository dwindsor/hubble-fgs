#!/bin/bash

set -xeu

CLUSTER_NAME="fgs-cli-ci"
SCRIPT_DIR="$(realpath $(dirname "${BASH_SOURCE[0]}"))"
LOGS_DIR="${1:-$SCRIPT_DIR/logs}"
cd "$SCRIPT_DIR"

if ! command -v kind; then
    echo "kind is not in \$PATH! Bailing out!" 1>&2
    exit -1
fi

if ! kind get clusters | grep "$CLUSTER_NAME" &>/dev/null; then
    echo "Cluster \"$CLUSTER_NAME\" does not exist! Bailing out!" 1>&2
    exit -1
fi

dump_logs() {
    kubectl cluster-info --context "kind-$CLUSTER_NAME"

    mkdir -p "$LOGS_DIR"
    cd "$LOGS_DIR"
    kubectl get pods --selector=app.kubernetes.io/name=hubble-enterprise \
      -n kube-system -o custom-columns=name:metadata.name --no-headers \
      | xargs -I{} sh -c 'kubectl logs -c enterprise -n kube-system {} > ./hubble-enterprise-pod-{}.log'
    kubectl get pods --selector=app.kubernetes.io/name=hubble-enterprise \
      -n kube-system -o custom-columns=name:metadata.name --no-headers \
      | xargs -I{} kubectl cp -c enterprise -n kube-system {}:/var/run/cilium/hubble/fgs.log ./hubble-fgs-{}-fgs.log
    cat ./hubble-fgs*.log | jq > fgs.json
    rm -f ./hubble-fgs*.log
}

dump_logs
