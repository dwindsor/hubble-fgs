#!/bin/bash
####################################################################
#
# File: launch_sas.sh
#
# Description:
#     Launch the DPU Sim container and start the NSIM & Hal process'
#
# Copyright (c) 2024 by cisco Systems, Inc.
# All rights reserved.
#
#
# $Id: $
#####################################################################

#set -x
env ; echo
NO_ADS=${NO_ADS:-0}
if [ $NO_ADS = 0 ]; then
    DOCKER_CMD=sysdocker
    DSC_PATH=/dsc
else
    DOCKER_CMD=docker
    DSC_PATH=./dsc
fi
VER=${VER:-v1}
TIMEOUT=${TIMEOUT:-120}

setup_docker_env () {
    
    CONTAINER="hypershield/naples:$VER"
    # set instance to unique name
    DSC_INSTANCE=${DSC_INSTANCE:-naples-$VER}
    #DSC_DIR=/dsc/$DSC_INSTANCE/
    DSC_DIR=$DSC_PATH/$DSC_INSTANCE/

    # create a dir so we can mount logs,cores
    # from this DSC instance into this dir
    mkdir -p $DSC_DIR/data
    mkdir -p $DSC_DIR/var/log/pensando
    mkdir -p $DSC_DIR/obfl

    usr=$(awk -F: '($3>=1000)&&($1!="nobody"&&$1!="ubuntu")&&($1=="runner"){print $1}' /etc/passwd)

    # If 'runner' exists, use it; otherwise, pick the first valid non-root user
    if [ -n "$usr" ]; then
        echo "Using 'runner' user."
    else
        # If 'runner' doesn't exist, select the first non-root user
        usr=$(awk -F: '($3>=1000)&&($1!="nobody"&&$1!="ubuntu"){print $1; exit}' /etc/passwd)
        echo "Using the first non-root user: $usr"
    fi
    chown "$usr" -R "$DSC_PATH"

    if [ $NO_ADS = 0 ]; then
        mkdir -p $DSC_DIR/../sdk
        cd /isan/bin/ && tar -xvzf /sdk/s1hal.tgz && cd -
    fi
}

setup_dsc_env () {
    MODE="cloud"
    # set this if this FRU mac to be used by DSC
    # else it comes up with random mac address
    SYSUUID=${SYSUUID:-00:ae:cd:00:d5:c0}
    MODEL_LOGGING_EN=${MODEL_LOGGING_EN:-0}
    RECOVERY_EN=${RECOVERY_EN:-0}

    # TODO: move to EXPOSE instead
    # grpc port for pds agent
    PDS_GRPC_PORT_API=11357
    # grpc port for upgrade manager
    PDS_GRPC_PORT_UPGMGR=11358
    # grpc port for operd
    PDS_GRPC_PORT_OPERD=11359
    # grpc port for operd default plugin
    PDS_GRPC_PORT_OPERD_PEN_PLUGIN=11360
    # grpc port for sysmgr
    PDS_GRPC_PORT_SYSMGR=11363

    PDS_GRPC_PORT_MIN=${PDS_GRPC_PORT_API}
    PDS_GRPC_PORT_MAX=${PDS_GRPC_PORT_SYSMGR}

    if [ -z "$BIND_GRPC_PORTS" ]; then
        port_opts="$PDS_GRPC_PORT_MIN-$PDS_GRPC_PORT_MAX:$PDS_GRPC_PORT_MIN-$PDS_GRPC_PORT_MAX/tcp"
        if [ -z "$DSC_IP" ]; then
            ip_opts=""
        else
            ip_opts="$DSC_IP:"
        fi
        PORT_OPTS=" -p ${ip_opts}${port_opts}"
    else
        PORT_OPTS=""
    fi

    MOUNT_OPTS="--mount type=bind,source=$DSC_DIR/data,target=/data"
    MOUNT_OPTS+=" --mount type=bind,source=$DSC_DIR/var/log/pensando,target=/var/log/pensando"
    MOUNT_OPTS+=" --mount type=bind,source=$DSC_DIR/obfl,target=/obfl"
}

setup_network_config () {
    sysctl -w net.ipv6.conf.all.disable_ipv6=0
    sysctl -w net.ipv6.conf.default.disable_ipv6=0
    sysctl -w net.ipv6.conf.lo.disable_ipv6=0
}

cleanup_docker () {
    echo "Cleaning up docker image from registry..."
    $DOCKER_CMD rmi -f hypershield/naples:$VER
}

load_docker() {
  $DOCKER_CMD images | grep hypershield/naples
  if [ "$DPUIMG" == "" -a -e /dsc/naples-docker-$VER.tgz ] ; then
    DPUIMG=/dsc/naples-docker-v1.tgz
  fi
  if [ "$DPUIMG" == "" ] ; then
    echo "Can't load DPU container image"
    exit 1
  fi
  echo "Loading DPU container image $DPUIMG"
  $DOCKER_CMD image load -i $DPUIMG
  return
}

run_docker () {
    if [ -n "$1" ]; then
        local network_opt="--network=$1"
    fi
    $DOCKER_CMD run -it -d --rm --privileged \
        --name $DSC_INSTANCE \
        $PORT_OPTS \
        $MOUNT_OPTS \
        $network_opt \
        --sysctl net.ipv6.conf.all.disable_ipv6=0 \
        --sysctl net.ipv6.conf.default.disable_ipv6=0 \
        --sysctl net.ipv6.conf.lo.disable_ipv6=0 \
        -e HNTAP_CFG_PATH=$HNTAP_CFG_PATH \
        -e MODEL_LOGGING_EN=$MODEL_LOGGING_EN \
        -e RECOVERY_EN=$RECOVERY_EN \
        -e MODE=$MODE \
        -e SYSUUID=$SYSUUID \
        -e DEVICE_OPER_MODE=$DEVICE_OPER_MODE \
        -e HAL_GRPC_PORT=$PDS_GRPC_PORT_API \
        "$CONTAINER"
    echo ; echo "DSC $DSC_INSTANCE started" ; echo
}

connect_to_docker () {
    # wait for container to start
    sleep 30
    $DOCKER_CMD exec -it $DSC_INSTANCE bash
}

setup_bitw_smart_switch_env () {
    DEVICE_OPER_MODE="bitw-smart-switch"
    HNTAP_CFG_PATH="/nic/conf/hntap-cfg.json"
}

setup_naples_env () {
    export DSC_INSTANCE=${DSC_INSTANCE:-naples-$VER}
    export DSC_INSTANCE_NETNS=`docker inspect -f '{{.State.Pid}}' $DSC_INSTANCE`
    mkdir -p /var/run/netns
    ln -sf /proc/$DSC_INSTANCE_NETNS/ns/net /var/run/netns/$DSC_INSTANCE_NETNS
    # dsc uplink interfaces
    UPLINK_INTF1=Eth1-1
    UPLINK_INTF2=Eth1-2
    UPLINK_INTF3=dsc0
}

counter=0
move_naples_uplink_interfaces () {
    printf "   Waiting for the tap interfaces to come up "
    while [ "$(ip netns exec $DSC_INSTANCE_NETNS [ -d /sys/class/net/$UPLINK_INTF1 ] || echo 1)" = "1" ] ; do
        sleep 1
        counter=$((counter+1))
        printf "."
        if [ "$counter" -eq "$TIMEOUT" ] ; then
          echo "Timed out waiting for uplink tap interaces, exiting."
          exit 1
        fi
    done
    echo ; echo "Interface bring up took $counter seconds."
    sleep 20
    # If we move these too soon the dp-app core dumps
    ip netns exec $DSC_INSTANCE_NETNS ip link show $UPLINK_INTF1
    ip netns exec $DSC_INSTANCE_NETNS ip link set dev $UPLINK_INTF1 netns 1
    ip netns exec $DSC_INSTANCE_NETNS ip link set dev $UPLINK_INTF2 netns 1
    ip netns exec $DSC_INSTANCE_NETNS ip link set dev $UPLINK_INTF3 netns 1
    ip link set $UPLINK_INTF1 up
    ip link set mtu 9440 dev $UPLINK_INTF1
    ip link set $UPLINK_INTF2 up
    ip link set mtu 9440 dev $UPLINK_INTF2
    ip link set $UPLINK_INTF3 up
    ip link set mtu 9440 dev $UPLINK_INTF3
    ip addr add 192.168.1.101/24 dev dsc0
    sleep 1
    ip link show $UPLINK_INTF1 && ip link show $UPLINK_INTF2 && ip link show $UPLINK_INTF3
    echo
}

echo "Launching DPU Sim container"
setup_docker_env
setup_dsc_env
setup_network_config
setup_bitw_smart_switch_env
cleanup_docker
load_docker
run_docker
if [ $NO_ADS = 0 ]; then
    echo "Launching NPU Sim"
    cp -r /sdk/s1sdklibs/*so* /usr/lib64/.ip link 
    cp -r /sdk/s1sdklibs/libprotobuf-c-rpc.so.0.0.0 /usr/lib/x86_64-linux-gnu/.
    DCHAL_SWITCH_TYPE=LAKEFRONT /sdk/launch_s1.sh
fi
echo "Move DPU Sim interfaces to NPU Sim's Parent Container"
setup_naples_env
move_naples_uplink_interfaces

exit 0