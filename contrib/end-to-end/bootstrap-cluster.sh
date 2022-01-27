#!/bin/bash

set -xeu

CLUSTER_NAME="fgs-cli-ci"
PROJECT_ROOT="$(realpath $(dirname "${BASH_SOURCE[0]}")/../..)"
cd "$PROJECT_ROOT"

if ! command -v kind; then
    echo "kind is not in \$PATH! Bailing out!" 1>&2
    exit -1
fi

bootstrap_cluster() {
    if ! kind get clusters | grep "$CLUSTER_NAME" &>/dev/null; then
        echo "Creating a new cluster \"$CLUSTER_NAME\"..." 1>&2
        kind create cluster --name "$CLUSTER_NAME" --wait=2m
    else
        echo "Cluster \"$CLUSTER_NAME\" already exists!" 1>&2
    fi
    kubectl cluster-info --context "kind-$CLUSTER_NAME"

    echo "Installing Cilium..." 1>&2
    cilium install --cluster-name="$CLUSTER_NAME" \
            --config monitor-aggregation=none

    echo "Enabling Hubble..." 1>&2
    cilium hubble enable
}

bootstrap_cluster
