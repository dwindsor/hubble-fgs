#!/usr/bin/env bash
set -euo pipefail

# renovate: datasource=github-releases depName=mikefarah/yq
yq_version=4.31.1

bundle_major=$(echo "$DOCKER_IMAGE_TAG" | cut -d \. -f 1)
bundle_major=${bundle_major#v}
bundle_minor=$(echo "$DOCKER_IMAGE_TAG" | cut -d \. -f 2)
bundle_zversion=$(echo "$DOCKER_IMAGE_TAG" | cut -d \. -f 3-)
index_file=install/olm/catalog/index.yaml

IMAGE_REPOSITORY="${IMAGE_REPOSITORY:-}"

bundle=$(docker run --rm -v "$(git rev-parse --show-toplevel)":/workdir mikefarah/yq:${yq_version} ".name | select(. == \"tetragon-operator.${DOCKER_IMAGE_TAG}\")" /workdir/${index_file})
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
  local -n maxz_name=$2
  local -n exist_minor=$3
  local minor=$4
  for entry in "${entries[@]}"; do
    # entry is a single json snippet representing a single entry
    if [[ $minor == $(echo $entry | cut -d \. -f 3) ]]
    then
      exist_minor=true
      if [ -z "$maxz_name" ]
      then
        maxz_name=$(echo "$entry" | docker run -i --rm mikefarah/yq:${yq_version} '.name' -)
      fi
      z=$(echo $entry | cut -d \. -f 4)
      z=$(echo $z | cut -d \" -f1)
      if [[ $maxz < $z ]]
      then
        maxz=$z
        maxz_name=$(echo "$entry" | docker run -i --rm mikefarah/yq:${yq_version} '.name' -)
        echo "setting maxz ${maxz_name}"
      fi
    fi
  done
}

maxz_for_current=0
maxz_for_current_name=""
exist_z_for_current_minor=false
retrieve_maxz maxz_for_current maxz_for_current_name exist_z_for_current_minor $bundle_minor

if [[ "$exist_z_for_current_minor" == "true" ]]
then
   echo "highest .z for the current minor version ${maxz_for_current}"
   docker run --rm -v "$(git rev-parse --show-toplevel)":/workdir --user "$(id -u):$(id -g)" mikefarah/yq:${yq_version} e -i "select(.schema == \"olm.channel\").entries = .entries + {\"name\": \"tetragon-operator.${DOCKER_IMAGE_TAG}\", \"replaces\": \"${maxz_for_current_name}\", \"skipRange\": \">=${bundle_major}.${bundle_minor}.0 <${bundle_major}.${bundle_minor}.${bundle_zversion}\"}" /workdir/${index_file}
else
    echo "no existing bundle for the current minor version, searching the previous one"
    maxz_for_previous=0
    maxz_for_previous_name=""
    exist_z_for_previous_minor=false
    previous_minor=$(( bundle_minor - 1 ))
    retrieve_maxz maxz_for_previous maxz_for_previous_name exist_z_for_previous_minor $previous_minor
    if [[ ! $exist_z_for_previous_minor ]]
    then
       echo "error: no bundle found for the previous minor version"
       exit 1
    fi
    echo "highest .z for the previous minor version $maxz_for_previous"
    docker run --rm -v "$(git rev-parse --show-toplevel)":/workdir --user "$(id -u):$(id -g)" mikefarah/yq:${yq_version} e -i "select(.schema == \"olm.channel\").entries = .entries + {\"name\": \"tetragon-operator.${DOCKER_IMAGE_TAG}\", \"replaces\": \"${maxz_for_previous_name}\", \"skipRange\": \">=${bundle_major}.${previous_minor}.${maxz_for_previous} <${bundle_major}.${bundle_minor}.${bundle_zversion}\"}" /workdir/${index_file}
fi

docker run --rm -v "$(git rev-parse --show-toplevel)":/workdir --user "$(id -u):$(id -g)" quay.io/operator-framework/opm:latest validate /workdir/install/olm/catalog
