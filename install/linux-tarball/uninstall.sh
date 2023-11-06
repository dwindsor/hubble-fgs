#!/usr/bin/env bash

set -xu

if [ "$(id -u)" -ne 0 ]; then
        echo "Error: to uninstall Tetragon Enterprise please run as root." >&2
        exit 1
fi

# Cleanup old name
systemctl stop hubble-fgs
systemctl disable hubble-fgs

systemctl stop tetragon-enterprise
systemctl disable tetragon-enterprise

rm -fr /usr/lib/systemd/system/hubble-fgs.service
rm -fr /usr/lib/systemd/system/tetragon-enterprise.service

# Cleanup old systemd service
rm -f /etc/systemd/system/default.target.wants/tetragon-enterprise.service

# Cleanup systemd state
systemctl daemon-reload

# remove binaries
rm -f /usr/local/bin/tetragon
rm -f /usr/local/bin/tetra

# remove legacy symbolic links
rm -f /usr/local/bin/hubble-fgs
rm -f /usr/local/bin/hubble-enterprise
rm -f /usr/local/bin/hubble-fgs-printer

rm -fr /usr/local/lib/hubble-fgs/
