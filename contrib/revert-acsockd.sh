#!/usr/bin/env bash
# Revert disable-acsockd.sh: unmask and start Cisco AnyConnect acsockd.service.
set -euo pipefail

echo "==> Unmasking acsockd.service"
sudo systemctl unmask acsockd.service

echo "==> Enabling acsockd.service (auto-start on boot)"
sudo systemctl enable acsockd.service

echo "==> Starting acsockd.service"
sudo systemctl start acsockd.service

echo
echo "acsockd.service is re-enabled and running."
echo "Check with: contrib/status-acsockd.sh"
