#!/bin/sh
set -e
ARGS=""
if [ -n "$AGW_CONFIG" ]; then
    ARGS="$ARGS --config=$AGW_CONFIG"
fi
if [ -n "$AGW_NETWORK_POLICY" ]; then
    ARGS="$ARGS --network-policy=$AGW_NETWORK_POLICY"
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
if [ -n "$AGW_VRF_MAP" ]; then
    ARGS="$ARGS --vrf-map=$AGW_VRF_MAP"
fi
if [ "$AGW_DEBUG" = "true" ]; then
    ARGS="$ARGS --debug"
fi
if [ -n "$AGW_K8S_SERVICE_ACCOUNT_AUTH" ]; then
    ARGS="$ARGS --k8s-service-account-auth=$AGW_K8S_SERVICE_ACCOUNT_AUTH"
fi
echo "Starting AGW with arguments:$ARGS"
exec /usr/src/app/agw $ARGS
