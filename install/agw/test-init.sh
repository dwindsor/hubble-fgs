#!/bin/bash
# Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Isovalent Inc and its suppliers, if any. The intellectual and technical
# concepts contained herein are proprietary to Isovalent Inc and its suppliers
# and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.  Dissemination of this information
# or reproduction of this material is strictly forbidden unless prior written
# permission is obtained from Isovalent Inc.
#
# Test init wrapper: prepares a headless test environment and then execs init.sh.
# This allows the agw-test container to use the same init.sh lifecycle as
# production (Fluent Bit, ntpd, crond, crash/restart logic) without requiring
# a real NXOS/gNMI server.

# 1. Clear stale state files so each container start is clean.
#    This prevents test-created VRFs/VLANs from leaking across sessions.
rm -f /iox_data/mock_gnmi.json
rm -f /iox_data/states/*.json

# 2. Build AGW flags from env vars into an agw wrapper script.
#    Renames the real agw binary to agw.real and creates a shell wrapper at
#    the same path that prepends the env-var-derived flags.
mv /usr/src/app/agw /usr/src/app/agw.real
cat > /usr/src/app/agw <<'WRAPPER'
#!/bin/bash
ARGS=""
[ -n "$AGW_CONFIG" ]             && ARGS="$ARGS --config=$AGW_CONFIG"
[ -n "$AGW_NETWORK_POLICY" ]     && ARGS="$ARGS --network-policy=$AGW_NETWORK_POLICY"
[ -n "$AGW_NETWORK_POLICY_DIR" ] && ARGS="$ARGS --network-policy-dir=$AGW_NETWORK_POLICY_DIR"
[ "$AGW_ENABLE_K8S" = "false" ]  && ARGS="$ARGS --enable-k8s=false"
[ "$AGW_ENABLE_NXOS" = "false" ] && ARGS="$ARGS --enable-nxos=false"
[ -n "$AGW_DPU_SERVER_ADDRESS" ] && ARGS="$ARGS --dpu-server-address=$AGW_DPU_SERVER_ADDRESS"
[ -n "$AGW_GOPS_ADDRESS" ]       && ARGS="$ARGS --gops-address=$AGW_GOPS_ADDRESS"
[ -n "$AGW_VRF_MAP" ]            && ARGS="$ARGS --vrf-map=$AGW_VRF_MAP"
[ "$AGW_DEBUG" = "true" ]        && ARGS="$ARGS --debug"
[ -n "$AGW_K8S_SERVICE_ACCOUNT_AUTH" ]      && ARGS="$ARGS --k8s-service-account-auth=$AGW_K8S_SERVICE_ACCOUNT_AUTH"
[ "$AGW_TIMESCAPE_CLIENT_ENABLE" = "true" ] && ARGS="$ARGS --timescape-client-enable=true"
[ -n "$AGW_TIMESCAPE_PASSWORD" ]  && ARGS="$ARGS --timescape-password=$AGW_TIMESCAPE_PASSWORD"
[ -n "$AGW_TIMESCAPE_ENDPOINT" ]  && ARGS="$ARGS --timescape-endpoint=$AGW_TIMESCAPE_ENDPOINT"
[ "$AGW_PROMETHEUS_CLIENT_ENABLE" = "true" ] && ARGS="$ARGS --prometheus-client-enable=true"
[ -n "$AGW_PROMETHEUS_PASSWORD" ] && ARGS="$ARGS --prometheus-password=$AGW_PROMETHEUS_PASSWORD"
[ -n "$AGW_PROMETHEUS_USERNAME" ] && ARGS="$ARGS --prometheus-username=$AGW_PROMETHEUS_USERNAME"
[ -n "$AGW_PROMETHEUS_ENDPOINT" ] && ARGS="$ARGS --prometheus-endpoint=$AGW_PROMETHEUS_ENDPOINT"
exec /usr/src/app/agw.real $ARGS "$@"
WRAPPER
chmod +x /usr/src/app/agw

# 3. Mock gNMI HTTPS endpoint so init.sh's curl check passes immediately.
#    init.sh loops doing: curl -k https://$NX_GRPC_IP:$NX_GRPC_PORT
#    socat with reuseaddr,fork keeps a persistent TLS listener that survives
#    across agw restarts (avoids TIME_WAIT port-rebinding failures).
NX_GRPC_IP="${NX_GRPC_IP:-127.0.0.1}"
NX_GRPC_PORT="${NX_GRPC_PORT:-50051}"
export NX_GRPC_IP NX_GRPC_PORT
MOCK_CERT="/tmp/mock-gnmi-cert.pem"
MOCK_KEY="/tmp/mock-gnmi-key.pem"
openssl req -x509 -newkey rsa:2048 -keyout "$MOCK_KEY" -out "$MOCK_CERT" \
    -days 1 -nodes -subj "/CN=localhost" 2>/dev/null
socat \
    "OPENSSL-LISTEN:${NX_GRPC_PORT},reuseaddr,fork,cert=${MOCK_CERT},key=${MOCK_KEY},verify=0" \
    SYSTEM:'echo -e "HTTP/1.0 200 OK\r\n\r\n"' >/dev/null 2>&1 &

# 4. Create /etc/sas.cfg so init.sh's headless-mode check does not fail.
#    If NXOS is disabled, set NX_AGENT_HEADLESS_MODE=1 to skip DNS resolution.
if [ "$AGW_ENABLE_K8S" = "false" ]; then
    echo "NX_AGENT_HEADLESS_MODE=1" > /etc/sas.cfg
else
    touch /etc/sas.cfg
fi

# 5. Hand off to the production entrypoint.
exec /usr/src/app/init.sh
