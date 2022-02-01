#!/bin/bash

set -xeu

CLUSTER_NAME="fgs-cli-ci"
PROJECT_ROOT="$(realpath $(dirname "${BASH_SOURCE[0]}")/../..)"
cd "$PROJECT_ROOT"

if ! command -v kind; then
    echo "kind is not in \$PATH! Bailing out!" 1>&2
    exit -1
fi

if ! kind get clusters | grep "$CLUSTER_NAME" &>/dev/null; then
    echo "Cluster \"$CLUSTER_NAME\" does not exist! Bailing out!" 1>&2
    exit -1
fi

install_fgs() {
    kubectl cluster-info --context "kind-$CLUSTER_NAME"

    echo "Building FGS image..." 1>&2
    make image

    echo "Loading FGS image into kind..." 1>&2
    kind load docker-image isovalent/hubble-fgs:latest --name "$CLUSTER_NAME"

    echo "Installing FGS..." 1>&2
    helm repo add isovalent https://helm.isovalent.com
    helm repo update
    helm uninstall -n kube-system hubble-enterprise || true
    echo "Waiting for existing FGS to be removed..." 1>&2
    kubectl wait -n kube-system --for=delete --all pod \
        -l app.kubernetes.io/name=hubble-enterprise --timeout=30s
    helm install hubble-enterprise isovalent/hubble-enterprise \
         --version 9999.9999.9999-dev \
         --set enterprise.image.repository=isovalent/hubble-fgs \
         --set enterprise.image.tag=latest \
         --set enterprise.exportAllowList="" \
         --set enterprise.enableTLSEvents=true \
         --namespace kube-system
    echo "Waiting for FGS to become ready..." 1>&2
    kubectl wait -n kube-system --for=condition=Ready --all pod \
        -l app.kubernetes.io/name=hubble-enterprise --timeout=30s
}

install_fgs
