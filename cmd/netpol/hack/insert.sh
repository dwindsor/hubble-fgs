#!/usr/bin/env bash

if [ "$#" -ne 6 ]; then
  echo "usage: insert.sh <vlan> <vrf> <srcIP> <srcPort> <dstIP> <dstPort>"
  echo "example: ./insert.sh 0 mgmt 192.168.0.1 2348 192.168.0.2 80"
  echo "NOTE: Assumes Timescape Lite! Edit insert.sh as needed."
  exit 1
fi

vlan=$1
vrf=$2
srcIP=$3
srcPort=$4
dstIP=$5
dstPort=$6
echo "$srcIP:$srcPort -> $dstIP:$dstPort (vlan: $vlan, vrf: $vrf)"

# clickhouse-client <<EOF
kubectl exec -i -n hubble-timescape pod/hubble-timescape-lite-0 --container clickhouse -- clickhouse-client -u timescape_lite <<EOF
INSERT INTO hubble.connection_logs (
  id, \`emitter/name\`,
  \`meta/inserted\`,
  \`window/since\`,
  \`window/until\`,

  \`source/family\`,
  \`source/network_device/name\`,
  \`source/network_device/ip\`,
  \`source/network_device/ip_protocol\`,
  \`source/network_device/port\`,
  \`source/network_device/vlan_id\`,
  \`source/network_device/vrf_name\`,

  \`destination/family\`,
  \`destination/network_device/name\`,
  \`destination/network_device/ip\`,
  \`destination/network_device/port\`,
  \`destination/network_device/vlan_id\`,
  \`destination/network_device/vrf_name\`,
) VALUES
  (generateUUIDv7(), 'test', now(), now(), now(),
    2, 'foo', '$srcIP', 6, '$srcPort', $vlan, 'management',
    2, 'bar', '$dstIP', '$dstPort', $vlan, 'management')
EOF
