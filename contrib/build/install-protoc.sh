#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

protoc_version="22.3"
arch=$(arch)
if [[ "${arch}" == "aarch64" ]]; then
  arch="aarch_64"
fi

curl --fail --show-error --silent --location \
  "https://github.com/protocolbuffers/protobuf/releases/download/v${protoc_version}/protoc-${protoc_version}-linux-${arch}.zip" \
    --output /tmp/protoc.zip

unzip /tmp/protoc.zip -x readme.txt -d /usr/local

# correct permissions for others
chmod o+rx /usr/local/bin/protoc
chmod o+rX -R /usr/local/include/google/

# 8ba23be9613c672d40ae261d2a1335d639bdd59b == tag: cmd/protoc-gen-go-grpc/v1.3.0
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@8ba23be9613c672d40ae261d2a1335d639bdd59b
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.30.0
go install github.com/mitchellh/protoc-gen-go-json@v1.1.0
go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@v1.5.1
