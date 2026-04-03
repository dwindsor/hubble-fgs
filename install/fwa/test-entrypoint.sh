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
if [ -n "$FWA_CONFIG" ]; then
    ARGS="$ARGS --config=$FWA_CONFIG"
fi
if [ -n "$FWA_NETWORK_POLICY" ]; then
    ARGS="$ARGS --network-policy=$FWA_NETWORK_POLICY"
fi
if [ "$FWA_ENABLE_DATAPLANE" = "false" ]; then
    ARGS="$ARGS --enable-dataplane=false"
fi
if [ "$FWA_ENABLE_AGW" = "false" ]; then
    ARGS="$ARGS --enable-agw=false"
fi
if [ "$FWA_ENABLE_LOGGER" = "false" ]; then
    ARGS="$ARGS --enable-logger=false"
fi
if [ -n "$FWA_SERVER_ADDRESS" ]; then
    ARGS="$ARGS --server-address=$FWA_SERVER_ADDRESS"
fi
if [ "$FWA_DEBUG" = "true" ]; then
    ARGS="$ARGS --debug"
fi
if [ "$FWA_ENABLE_EVENT_STREAM" = "false" ]; then
    ARGS="$ARGS --enable-event-stream=false"
fi
if [ -n "$FWA_DP_SOCKET_PATH" ]; then
    ARGS="$ARGS --dp-socket-path=$FWA_DP_SOCKET_PATH"
fi
echo "Starting FWA with arguments:$ARGS"
exec /usr/src/app/fwa $ARGS
