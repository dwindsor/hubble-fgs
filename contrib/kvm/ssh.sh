#!/bin/bash

set -eu

CONF_DIR="$(realpath $(dirname "${BASH_SOURCE[0]}"))"
source "$CONF_DIR/conf"

ssh  -oUserKnownHostsFile=/dev/null -oStrictHostKeyChecking=no -p "$SSHPORT" root@localhost $@
