#!/usr/bin/env bash
set -euo pipefail

# renovate: datasource=github-releases depName=mikefarah/yq
yq_version=4.31.1

bundle_major=$(echo "$DOCKER_IMAGE_TAG" | cut -d \. -f 1)
bundle_minor=$(echo "$DOCKER_IMAGE_TAG" | cut -d \. -f 2)
bundle_zversion=$(echo "$DOCKER_IMAGE_TAG" | cut -d \. -f 3)

index_file=install/olm/catalog/index.yaml

IMAGE_REPOSITORY="${IMAGE_REPOSITORY:-}"

bundle=$(docker run --rm -v "$(git rev-parse --show-toplevel)":/workdir mikefarah/yq:${yq_version} ".name | select(. == \"tetragon-operator.v${DOCKER_IMAGE_TAG}\")" /workdir/${index_file})
if [ -n "$bundle" ]
then
  echo "bundle tetragon-operator.v${DOCKER_IMAGE_TAG} already present in catalog index"
  exit 1
fi

# Add bundle to index
docker run --rm -v "$(git rev-parse --show-toplevel)":/workdir quay.io/operator-framework/opm:latest render ${IMAGE_REPOSITORY}/tetragon-operator-bundle:${DOCKER_IMAGE_TAG} --output=yaml >> ${index_file}

# Add bundle to channel
entries=$(docker run --rm -v "$(git rev-parse --show-toplevel)":/workdir mikefarah/yq:${yq_version} '.entries[]' /workdir/${index_file})
# output each entry as a single line json
readarray entries < <(docker run --rm -v "$(git rev-parse --show-toplevel)":/workdir mikefarah/yq:${yq_version} -o=j -I=0 '.entries[]' /workdir/${index_file})

function retrieve_maxz() {
  local -n maxz=$1
  local -n exist_minor=$2
  local minor=$3
  for entry in "${entries[@]}"; do
    # entry is a single json snippet representing a single entry
    name=$(echo "$entry" | docker run -i --rm mikefarah/yq:${yq_version} '.name' -)
    if [[ $minor == $(echo $entry | cut -d \. -f 3) ]]
    then
      exist_minor=true
      z=$(echo $entry | cut -d \. -f 4)
      z=$(echo $z | cut -d \" -f1)
      if [[ $maxz < $z ]]
      then
        maxz=$z
      fi
    fi
  done
}

maxz_for_current=0
exist_z_for_current_minor=false
retrieve_maxz maxz_for_current exist_z_for_current_minor $bundle_minor

if [[ "$exist_z_for_current_minor" == "true" ]]
then
   echo "highest .z for the current minor version $maxz_for_current"
   docker run --rm -v "$(git rev-parse --show-toplevel)":/workdir mikefarah/yq:${yq_version} e -i "select(.schema == \"olm.channel\").entries = .entries + {\"name\": \"tetragon-operator.v${DOCKER_IMAGE_TAG}\", \"replaces\": \"tetragon-operator.v${bundle_major}.${bundle_minor}.${maxz_for_current}\", \"skipRange\": \">=${bundle_major}.${bundle_minor}.0 <${bundle_major}.${bundle_minor}.${bundle_zversion}\"}" /workdir/${index_file}
else
    echo "no existing bundle for the current minor version, searching the previous one"
    maxz_for_previous=0
    exit_z_for_previous_minor=false
    previous_minor=$(( bundle_minor - 1 ))
    retrieve_maxz maxz_for_previous exist_z_for_previous_minor $previous_minor
    if [[ ! $exist_z_for_previous_minor ]]
    then
       echo "error: no bundle found for the previous minor version"
       exit 1
    fi
    echo "highest .z for the previous minor version $maxz_for_previous"
   docker run --rm -v "$(git rev-parse --show-toplevel)":/workdir mikefarah/yq:${yq_version} e -i "select(.schema == \"olm.channel\").entries = .entries + {\"name\": \"tetragon-operator.v${DOCKER_IMAGE_TAG}\", \"replaces\": \"tetragon-operator.v${bundle_major}.${previous_minor}.${maxz_for_previous}\", \"skipRange\": \">=${bundle_major}.${previous_minor}.${maxz_for_previous} <${bundle_major}.${bundle_minor}.${bundle_zversion}\"}" /workdir/${index_file}
fi

docker run --rm -v "$(git rev-parse --show-toplevel)":/workdir quay.io/operator-framework/opm:latest validate /workdir/install/olm/catalog
