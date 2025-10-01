#!/usr/bin/env bash

set -eu

SRC_DIR=$(dirname -- "$(readlink -f -- "$0")")

cp -vRf ${SRC_DIR}/usr/local/* /usr/local/
# legacy aliases
ln -s /usr/local/bin/tetragon /usr/local/bin/hubble-fgs
ln -s /usr/local/bin/tetra /usr/local/bin/hubble-enterprise
ln -s /usr/local/bin/tetra /usr/local/bin/hubble-fgs-printer

cp -vf /usr/local/lib/tetragon/systemd/tetragon-enterprise.service /usr/lib/systemd/system/tetragon-enterprise.service

install -d /etc/tetragon/tetragon.conf.d/
install -d /etc/tetragon/tetragon.tp.d/
install -d /etc/tetragon/tetragon.policies.d/

systemctl daemon-reload
systemctl enable tetragon-enterprise
systemctl start tetragon-enterprise

echo "Tetragon Enterprise installed successfully!"
