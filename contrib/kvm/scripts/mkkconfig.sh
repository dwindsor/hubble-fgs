#!/bin/bash

set -xeu -o pipefail

CONF_DIR="$(realpath $(dirname "${BASH_SOURCE[0]}")/..)"
source $CONF_DIR/conf

touch $KCONFIG
export KCONFIG=$(realpath $KCONFIG)

pushd $KSRCDIR

