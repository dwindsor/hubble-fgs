#!/bin/sh
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
if [ -n "$FWA_DP_SOCKET_PATH" ]; then
    ARGS="$ARGS --dp-socket-path=$FWA_DP_SOCKET_PATH"
fi
echo "Starting FWA with arguments:$ARGS"
exec /usr/src/app/fwa $ARGS
