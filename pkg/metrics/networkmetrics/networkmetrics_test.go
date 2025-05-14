//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package networkmetrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestTXBytesTotal(t *testing.T) {
	assert.NoError(t, testutil.CollectAndCompare(txBytesTotal, strings.NewReader("")))
	Collect(&allowExample)
	expected := strings.NewReader(`# HELP tetragon_network_txbytes_total Number of bytes transmitted.
# TYPE tetragon_network_txbytes_total counter
tetragon_network_txbytes_total{destination_name="default:WORKLOAD_KIND_SERVICE:kubernetes",destination_namespace="default",destination_port="443",destination_type="DESTINATION_TYPE_KUBERNETES",destination_workload="kubernetes",namespace="example-namespace",policy="my-network-policy",protocol="NETWORK_PROTOCOL_TYPE_TCP",rule="Allow TCP traffic to Kubernetes API server on port 443",workload="example-workload"} 1
`)
	assert.NoError(t, testutil.CollectAndCompare(txBytesTotal, expected))
}

func TestDroppedSessionsTotal(t *testing.T) {
	assert.NoError(t, testutil.CollectAndCompare(droppedSessionsTotal, strings.NewReader("")))
	Collect(&dropExample)
	expected := strings.NewReader(`# HELP tetragon_network_dropped_sessions_total Number of sessions that got dropped by a Tetragon network policy rule.
# TYPE tetragon_network_dropped_sessions_total counter
tetragon_network_dropped_sessions_total{destination_name="bad.example.com",destination_namespace="",destination_port="80",destination_type="DESTINATION_TYPE_DNS",destination_workload="",namespace="example-namespace",policy="my-network-policy",protocol="NETWORK_PROTOCOL_TYPE_TCP",rule="Drop TCP traffic to bad.example.com on port 80",workload="example-workload"} 0
`)
	assert.NoError(t, testutil.CollectAndCompare(droppedSessionsTotal, expected))
}
