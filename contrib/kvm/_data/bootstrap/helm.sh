#!/usr/bin/env bash
set -euxo pipefail

. /etc/profile

curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
