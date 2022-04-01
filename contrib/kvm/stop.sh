#!/bin/bash

set -eu

# Use pgrep if it exists on the machine, but fall back to grep and awk for portability
if command -v pgrep &>/dev/null; then
    QEMU_PID="$(pgrep "qemu-system" | head -n 1)"
else
    QEMU_PID="$(ps ax | grep "qemu-system" | awk 'NR==1{print $1}')"
fi

if [ ! -z "$QEMU_PID" ]; then
    echo "Killing $QEMU_PID!" 1>&2
    sudo kill "$QEMU_PID"
else
    echo "VM is not running!" 1>&2
fi
