#!/bin/bash

set -euo pipefail

VM="<your vm name>"
ZONE="<vm zone>"

ip() {
    echo $(gcloud compute instances describe --zone $ZONE $VM --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
}

start() {
    gcloud compute instances start --zone $ZONE $VM

    # Update the gce entry in .ssh/config with new ip address. If you use a
    # name other than gce, update it here
    local new_ip=$(ip)
    sed -i -e "/^host gce$/,/^$/ s/HostName .*/HostName $new_ip/" ~/.ssh/config
}

stop() {
    gcloud compute instances stop --zone $ZONE $VM
}

describe() {
    gcloud compute instances describe --zone $ZONE $VM
}

labels() {
    gcloud compute instances describe --zone $ZONE $VM --format="get(labels)"
}

state() {
    gcloud compute instances describe --zone $ZONE $VM --format="get(status)" | awk '{print tolower($0)}'
}

machine() {
    gcloud compute instances set-machine-type $VM --zone $ZONE --machine-type $1
}

case "${1-help}" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    ip)
        ip
        ;;
    describe)
        describe
        ;;
    labels)
	labels
	;;
    state|status)
        state
        ;;
    ssh)
	shift 1
        ssh gke "$@"
        ;;
    small)
        machine e2-standard-2
        ;;
    normal)
        machine e2-standard-4
        ;;
    large)
        machine e2-standard-8
        ;;
    huge)
        machine e2-standard-16
        ;;
    *)
        echo "Usage: $0 {start|stop|state|status|ssh|ip|describe|labels|small|normal|large|huge}"
        exit 2
        ;;
esac
