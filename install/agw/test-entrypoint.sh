#!/bin/sh
# Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Isovalent Inc and its suppliers, if any. The intellectual and technical
# concepts contained herein are proprietary to Isovalent Inc and its suppliers
# and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.  Dissemination of this information
# or reproduction of this material is strictly forbidden unless prior written
# permission is obtained from Isovalent Inc.

set -e
ARGS=""
AGW_FLB_SOCKET_PATH="${AGW_FLB_SOCKET_PATH:-/run/cisco/fluentbit_agw.sock}"
AGW_FLB_CONFIG_PATH="${AGW_FLB_CONFIG_PATH:-/data/hypershield/daflogger.yaml}"
FLUENT_BIT_CONFIG="${FLUENT_BIT_CONFIG:-$AGW_FLB_CONFIG_PATH}"
FLUENT_BIT_METRICS_URL="${FLUENT_BIT_METRICS_URL:-http://localhost:2020/api/v1/metrics}"
FLUENT_BIT_READY_ATTEMPTS="${FLUENT_BIT_READY_ATTEMPTS:-60}"
FLUENT_BIT_READY_SLEEP_SECONDS="${FLUENT_BIT_READY_SLEEP_SECONDS:-1}"
if [ -n "$AGW_CONFIG" ]; then
    ARGS="$ARGS --config=$AGW_CONFIG"
fi
if [ -n "$AGW_NETWORK_POLICY" ]; then
    ARGS="$ARGS --network-policy=$AGW_NETWORK_POLICY"
fi
if [ -n "$AGW_NETWORK_POLICY_DIR" ]; then
    ARGS="$ARGS --network-policy-dir=$AGW_NETWORK_POLICY_DIR"
fi
if [ "$AGW_ENABLE_K8S" = "false" ]; then
    ARGS="$ARGS --enable-k8s=false"
fi
if [ "$AGW_ENABLE_NXOS" = "false" ]; then
    ARGS="$ARGS --enable-nxos=false"
fi
if [ -n "$AGW_DPU_SERVER_ADDRESS" ]; then
    ARGS="$ARGS --dpu-server-address=$AGW_DPU_SERVER_ADDRESS"
fi
if [ -n "$AGW_GOPS_ADDRESS" ]; then
    ARGS="$ARGS --gops-address=$AGW_GOPS_ADDRESS"
fi
if [ -n "$AGW_VRF_MAP" ]; then
    ARGS="$ARGS --vrf-map=$AGW_VRF_MAP"
fi
if [ "$AGW_DEBUG" = "true" ]; then
    ARGS="$ARGS --debug"
fi
if [ -n "$AGW_K8S_SERVICE_ACCOUNT_AUTH" ]; then
    ARGS="$ARGS --k8s-service-account-auth=$AGW_K8S_SERVICE_ACCOUNT_AUTH"
fi
if [ "$AGW_TIMESCAPE_CLIENT_ENABLE" = "true" ]; then
    ARGS="$ARGS --timescape-client-enable=true"
fi
if [ -n "$AGW_TIMESCAPE_PASSWORD" ]; then
    ARGS="$ARGS --timescape-password=$AGW_TIMESCAPE_PASSWORD"
fi
if [ -n "$AGW_TIMESCAPE_ENDPOINT" ]; then
    ARGS="$ARGS --timescape-endpoint=$AGW_TIMESCAPE_ENDPOINT"
fi
if [ "$AGW_PROMETHEUS_CLIENT_ENABLE" = "true" ]; then
    ARGS="$ARGS --prometheus-client-enable=true"
fi
if [ -n "$AGW_PROMETHEUS_PASSWORD" ]; then
    ARGS="$ARGS --prometheus-password=$AGW_PROMETHEUS_PASSWORD"
fi
if [ -n "$AGW_PROMETHEUS_USERNAME" ]; then
    ARGS="$ARGS --prometheus-username=$AGW_PROMETHEUS_USERNAME"
fi
if [ -n "$AGW_PROMETHEUS_ENDPOINT" ]; then
    ARGS="$ARGS --prometheus-endpoint=$AGW_PROMETHEUS_ENDPOINT"
fi
if [ -n "$AGW_FLB_SOCKET_PATH" ]; then
    ARGS="$ARGS --flb-socket-path=$AGW_FLB_SOCKET_PATH"
fi
if [ -n "$AGW_FLB_CONFIG_PATH" ]; then
    ARGS="$ARGS --flb-config-path=$AGW_FLB_CONFIG_PATH"
fi

start_fluent_bit() {
    mkdir -p "$(dirname "$AGW_FLB_SOCKET_PATH")"
    echo "Starting Fluent Bit with config: $FLUENT_BIT_CONFIG"
    /usr/bin/fluent-bit -Y -c "$FLUENT_BIT_CONFIG" &
    FLUENT_BIT_PID=$!
}

http_get() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsS "$1" >/dev/null 2>&1
        return $?
    fi
    if command -v wget >/dev/null 2>&1; then
        wget -q -O /dev/null "$1" 2>/dev/null
        return $?
    fi
    return 127
}

wait_for_fluent_bit_ready() {
    i=0
    while [ "$i" -lt "$FLUENT_BIT_READY_ATTEMPTS" ]; do
        if http_get "$FLUENT_BIT_METRICS_URL"; then
            echo "Fluent Bit is ready at $FLUENT_BIT_METRICS_URL"
            return 0
        fi
        if ! kill -0 "$FLUENT_BIT_PID" 2>/dev/null; then
            echo "Fluent Bit exited before becoming ready"
            return 1
        fi
        i=$((i + 1))
        sleep "$FLUENT_BIT_READY_SLEEP_SECONDS"
    done
    echo "Timed out waiting for Fluent Bit readiness at $FLUENT_BIT_METRICS_URL"
    return 1
}

shutdown() {
    if [ -n "${AGW_PID:-}" ]; then
        kill "$AGW_PID" 2>/dev/null || true
    fi
    if [ -n "${FLUENT_BIT_PID:-}" ]; then
        kill "$FLUENT_BIT_PID" 2>/dev/null || true
    fi
    wait "${AGW_PID:-}" 2>/dev/null || true
    wait "${FLUENT_BIT_PID:-}" 2>/dev/null || true
}

trap 'shutdown; exit 143' INT TERM

start_fluent_bit

echo "Starting AGW with arguments:$ARGS"
/usr/src/app/agw $ARGS &
AGW_PID=$!

if ! wait_for_fluent_bit_ready; then
    shutdown
    exit 1
fi

EXIT_CODE=0
while :; do
    if ! kill -0 "$AGW_PID" 2>/dev/null; then
        wait "$AGW_PID" || EXIT_CODE=$?
        break
    fi
    if ! kill -0 "$FLUENT_BIT_PID" 2>/dev/null; then
        wait "$FLUENT_BIT_PID" || EXIT_CODE=$?
        break
    fi
    sleep 1
done

shutdown
exit "$EXIT_CODE"
