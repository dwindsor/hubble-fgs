#!/bin/bash

set -e
shopt -s expand_aliases

alias helm='docker run --rm -v $(pwd):/apps alpine/helm:3.11.2'
helm dependency update .
helm lint . --with-subcharts
helm template hubble-enterprise . | kubeval --strict --additional-schema-locations https://raw.githubusercontent.com/joshuaspence/kubernetes-json-schema/master

# Update README.md.
docker run --rm -v "$(pwd):/helm-docs" -u "$(id -u)" jnorwood/helm-docs:v1.11.0
