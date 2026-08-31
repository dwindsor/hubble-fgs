#!/usr/bin/env bash
# Disable Cisco AnyConnect acsockd.service so cgroup BPF programs can load.
# acsockd attaches its own cgroup BPF programs, which make Tetragon's network
# program attach fail with "operation not permitted". Masking symlinks the unit
# to /dev/null, preventing it from starting.
set -euo pipefail

echo "==> Stopping acsockd.service"
sudo systemctl stop acsockd.service

echo "==> Disabling acsockd.service (no auto-start on boot)"
sudo systemctl disable acsockd.service

echo "==> Masking acsockd.service"
sudo systemctl mask --now acsockd.service

echo "==> Stopping acsockd.service again (in case mask --now restarted it)"
sudo systemctl stop acsockd.service

echo
echo "acsockd.service is now disabled and masked. cgroup BPF programs should load."
echo "Check with: contrib/status-acsockd.sh"
