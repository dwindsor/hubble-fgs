#!/usr/bin/env bash

readonly BENCH_DURATION=15s
GIT_REV=${1:-unknown}
GCP_KEY=$2

set -eu

ulimit -l 262144

go test github.com/isovalent/hubble-fgs/pkg/bench -benchtime $BENCH_DURATION -timeout 30m -bench .
go run cmd/fgs-bench-publish/fgs-bench-publish.go pretty $GIT_REV "$GCP_KEY" results/*.json

