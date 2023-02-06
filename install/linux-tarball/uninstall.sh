#!/usr/bin/env bash

set -xu

if [ "$(id -u)" -ne 0 ]; then
        echo "Error: to uninstall Tetragon Enterprise please run as root." >&2
        exit 1
fi

systemctl stop hubble-fgs
systemctl disable hubble-fgs

rm -fr /usr/lib/systemd/system/hubble-fgs.service
# Cleanup systemd state
systemctl daemon-reload

rm -fr /usr/local/bin/hubble-fgs
rm -fr /usr/local/bin/hubble-fgs-printer
rm -fr /usr/local/bin/hubble-enterprise
rm -fr /usr/local/lib/hubble-fgs/
