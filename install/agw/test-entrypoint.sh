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
echo "Starting AGW with arguments:$ARGS"
exec /usr/src/app/agw $ARGS
