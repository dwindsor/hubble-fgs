#!/bin/bash

set -eu

CONF_DIR="$(realpath $(dirname "${BASH_SOURCE[0]}"))"
source "$CONF_DIR/conf"

usage() {
	echo "usage: ssh.sh [OPTIONS]" 1>&2
	echo "OPTIONS:" 1>&2
    echo "    --port   [NUMBER]  port to forward on the host for ssh access" 1>&2
}

args=( )
while [ $# -ge 1 ]; do
	if [ "$1" == "--help" ] ; then
        usage
        exit 1
	elif [ "$1" == "--port" ] ; then
		SSHPORT="$2"
		shift 2
    else
        args+=( $1 )
        shift 1
	fi
done

ssh  -oUserKnownHostsFile=/dev/null -oStrictHostKeyChecking=no -p "$SSHPORT" root@localhost "${args[@]}"
