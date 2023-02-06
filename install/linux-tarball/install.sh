#!/usr/bin/env bash

set -eu

SRC_DIR=$(dirname -- "$(readlink -f -- "$0")")

cp -vRf ${SRC_DIR}/usr/local/* /usr/local/

cp -vf /usr/local/lib/hubble-fgs/systemd/hubble-fgs.service /usr/lib/systemd/system/hubble-fgs.service

install -d /etc/hubble-fgs/hubble-fgs.conf.d/

systemctl daemon-reload
systemctl enable hubble-fgs
systemctl start hubble-fgs

echo "Hubble FGS / Tetragon Enterprise installed successfully!"
