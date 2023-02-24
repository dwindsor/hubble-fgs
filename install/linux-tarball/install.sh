#!/usr/bin/env bash

set -eu

SRC_DIR=$(dirname -- "$(readlink -f -- "$0")")

cp -vRf ${SRC_DIR}/usr/local/* /usr/local/

cp -vf /usr/local/lib/hubble-fgs/systemd/tetragon-enterprise.service /usr/lib/systemd/system/tetragon-enterprise.service

install -d /etc/hubble-fgs/hubble-fgs.conf.d/

systemctl daemon-reload
systemctl enable tetragon-enterprise
systemctl start tetragon-enterprise

echo "Tetragon Enterprise installed successfully!"
