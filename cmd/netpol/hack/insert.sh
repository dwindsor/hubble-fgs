#!/usr/bin/env bash

vlan=$1
srcIP=$2
srcPort=$3
dstIP=$4
dstPort=$5
echo "$srcIP:$srcPort -> $dstIP:$dstPort (vlan: $vlan)"

clickhouse-client <<EOF
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
