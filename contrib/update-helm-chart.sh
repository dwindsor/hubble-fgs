#!/usr/bin/env bash

set -ex

shopt -s expand_aliases
# renovate: datasource=docker
YQ_IMAGE=docker.io/mikefarah/yq:4.49.2@sha256:224eec1bdaf4903221117d65dd95a0f4f4a6d4e46c88e2c81e09398d1f2753a1
alias yq="docker run --rm -v \"$(pwd)\":/workdir --user \"$(id -u):$(id -g)\" $YQ_IMAGE"

if [ -z "$1" ] || [[ ! $1 =~ ^v[0-9]+\.[0-9]+\.[0-9]+.*$ ]]; then
  echo "USAGE: ./contrib/update-helm-chart.sh vX.Y.Z"
  exit 1
fi

version=$1
# Drop the leading "v" for Helm chart version.
semver="${version:1}"

# Update image tags
yq -i ".tetragon.image.tag = \"$version\"" install/kubernetes/enterprise/values.yaml
yq -i ".tetragonOperator.image.tag = \"$version\"" install/kubernetes/enterprise/values.yaml
yq -i ".tetragonAggregator.image.tag = \"$version\"" install/kubernetes/enterprise/values.yaml
# Update version label in default policies
find "install/kubernetes/enterprise/default-policies" -type f -name "*.yaml" -exec \
  yq ".metadata.labels.\"app.kubernetes.io/version\" = \"$semver\"" -i {} \;

# Generate full Helm chart
make -C $(git rev-parse --show-toplevel)/install/kubernetes
