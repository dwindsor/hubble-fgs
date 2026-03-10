#!/usr/bin/env bash

set -eu

xdir=$(dirname -- "$(readlink -f -- "$0")")

${xdir}/usr/local/bin/tetragon --bpf-lib ${xdir}/usr/local/lib/tetragon/bpf/ "$@"
