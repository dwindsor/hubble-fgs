#!/bin/bash

set -eu

CLUSTER_NAME="fgs-cli-ci"
PROJECT_ROOT="$(realpath $(dirname "${BASH_SOURCE[0]}")/../..)"

FGS_IMAGE=""
FGS_TAG=""
BTF_FILE=""

usage() {
	echo "usage: install-fgs.sh [OPTIONS]" 1>&2
	echo "OPTIONS:" 1>&2
    echo "    --image [IMAGE:TAG] use existing docker image instead of compiling a new one" 1>&2
    echo "    --btf   [FILE]      use btf file" 1>&2
}

while [ $# -ge 1 ]; do
	if [ "$1" == "--image" ]; then
        IFS=':'
        IMAGE_TAG_PAIR=( $2 )
        FGS_IMAGE="${IMAGE_TAG_PAIR[0]}"
        FGS_TAG="${IMAGE_TAG_PAIR[1]:-latest}"
		shift 2
	elif [ "$1" == "--btf" ]; then
        BTF_FILE="$(readlink -f "$2")"
		shift 2
    else
        usage
        exit 1
	fi
done

install_fgs() {
    if ! kind get clusters | grep "$CLUSTER_NAME" &>/dev/null; then
        echo "Cluster \"$CLUSTER_NAME\" does not exist! Bailing out!" 1>&2
        exit -1
    fi

    if ! command -v kind; then
        echo "kind is not in \$PATH! Bailing out!" 1>&2
        exit -1
    fi

    if [ -z "$FGS_IMAGE" ]; then
        echo "Building FGS image..." 1>&2
        pushd "$PROJECT_ROOT"
        make image
        popd
        FGS_IMAGE="isovalent/hubble-fgs"
        FGS_TAG="latest"
    fi

    echo "Loading FGS image into kind..." 1>&2
    kind load docker-image "$FGS_IMAGE:$FGS_TAG" --name "$CLUSTER_NAME"

    echo "Installing FGS..." 1>&2
    helm repo add isovalent https://helm.isovalent.com
    helm repo update
    helm uninstall -n kube-system hubble-enterprise --wait=true || true

    # Build up helm options
    declare -a helm_opts=("--version" "9999.9999.9999-dev" "--namespace" "kube-system")
    helm_opts+=("--set" "enterprise.image.repository=$FGS_IMAGE")
    helm_opts+=("--set" "enterprise.image.tag=$FGS_TAG")
    helm_opts+=("--set" "enterprise.exportAllowList=")
    helm_opts+=("--set" "enterprise.enableTLSEvents=true")
    helm_opts+=("--set" "enterprise.exportFileMaxSizeMB=50")
    if [ -f "$BTF_FILE" ]; then
        KIND_ID="$(docker ps -aqf "name=$CLUSTER_NAME-control-plane")"
        echo "Transferring $BTF_FILE to container $KIND_ID..." 1>&2
        docker cp "$BTF_FILE" "$KIND_ID:/btf"
        helm_opts+=("--set" "enterprise.btf=/btf")
        helm_opts+=("--set" "extraHostPathMounts[0].name=btf")
        helm_opts+=("--set" "extraHostPathMounts[0].mountPath=/btf")
        helm_opts+=("--set" "extraHostPathMounts[0].readOnly=true")
    fi

    helm install hubble-enterprise isovalent/hubble-enterprise "${helm_opts[@]}"


    echo "Waiting for FGS to become ready..." 1>&2
    for i in $(seq 10); do
        kubectl rollout status ds/hubble-enterprise -n kube-system --timeout=30s && break || sleep 10
    done
}

install_fgs
