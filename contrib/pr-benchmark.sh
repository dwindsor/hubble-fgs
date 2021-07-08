#!/usr/bin/env bash

readonly BENCH_DURATION=5s
GIT_REV=${1:-unknown}

set -eu

ulimit -l 262144


go test github.com/isovalent/hubble-fgs/pkg/bench -benchtime $BENCH_DURATION -timeout 30m -bench .

# get_ratio <fgs results> <baseline results> <datapoint>
get_ratio() {
	local FGS_RATE=$(jq -r $3 < results/$1)
	local BASE_RATE=$(jq -r $3 < results/$2)
	echo "scale=1; 100 * $FGS_RATE / $BASE_RATE" | bc -l
}

TCP_CRR_RATIO=$(get_ratio BenchmarkFgsTls_tcp.json BenchmarkBaseline_tcp.json .SourceStats.ActualConnRate)
TCP_RR_RATIO=$(get_ratio BenchmarkFgsTcpRequestResponse_tcp.json BenchmarkBaselineTcpRequestResponse.json .SourceStats.ActualReqRate)
TCP_TLS_RR_RATIO=$(get_ratio BenchmarkFgsTls_TcpRequestResponse_tcp.json BenchmarkBaselineTcpRequestResponse.json .SourceStats.ActualReqRate)
TLS_CRR_RATIO=$(get_ratio BenchmarkFgsTls_tls.json BenchmarkBaseline_tls.json .SourceStats.ActualConnRate)

body="
Benchmark results ($GIT_REV):
- TLS connection rate with FGS (tls enabled) vs baseline: ${TLS_CRR_RATIO}%
- TCP connection rate with FGS (tls enabled) vs baseline: ${TCP_CRR_RATIO}%
- TCP request response rate with FGS (no tls) vs baseline: ${TCP_RR_RATIO}%
- TCP request response rate with FGS (tls enabled) vs baseline: ${TCP_TLS_RR_RATIO}%
"
body="${body//'%'/'%25'}"
body="${body//$'\n'/'%0A'}"
body="${body//$'\r'/'%0D'}"
echo "::set-output name=body::$body"
