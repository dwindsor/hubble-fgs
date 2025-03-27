//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package checker_test

import (
	"context"
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/model/checker"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCheckApplicationEventModel(t *testing.T) {
	var err error
	var chk *checker.ApplicationModelChecker

	ctx := context.Background()

	model := &appModelV1.ApplicationModelEvent{
		ClusterName:      "foo",
		NodeName:         "foo-a5cf729e",
		Time:             &timestamppb.Timestamp{},
		ApplicationModel: &appModelV1.ApplicationModel{},
	}

	exprs := []string{`cluster_name == "foo" && node_name.matches("^" + cluster_name + "-[0-9a-f]+$")`}
	chk, err = checker.NewApplicationModelChecker()
	require.NoError(t, err)
	res, err := chk.CheckApplicationModelEvent(ctx, model, exprs)
	require.NoError(t, err)
	assert.True(t, res.Ok())

	exprs = []string{`cluster_name == "bar"`}
	res, err = chk.CheckApplicationModelEvent(ctx, model, exprs)
	require.NoError(t, err)
	assert.False(t, res.Ok())
}

func TestCheckApplicationEventModelJSON(t *testing.T) {
	var err error
	var chk *checker.ApplicationModelChecker

	ctx := context.Background()

	appModelEventJSON := `{"node_name":"ip-10-3-8-195.us-west-2.compute.internal","time":"2024-11-13T19:07:40.752283416Z","application_model":{"namespaces":[{"name":"hubble-enterprise","workloads":[{"name":"hubble-enterprise","kind":"WORKLOAD_KIND_DAEMONSET","processes":[{"name":"/usr/local/bin/ruby"}]}]}],"host":{"processes":[{"name":"/usr/local/aws-cli/v2/2.17.61/dist/aws","connections":[{"destination":{"ip":{"ip":"169.254.169.254"},"port":"80"},"stats":{"tx_bytes":"290542","rx_bytes":"627385"}}]},{"name":"/usr/sbin/logrotate"},{"name":"/usr/sbin/runc"},{"name":"/usr/sbin/xtables-nft-multi"}]}}}`

	exprs := []string{
		`node_name == "ip-10-3-8-195.us-west-2.compute.internal"`,
		`model.namespaces.exists_one(n, n.name == "hubble-enterprise" && n.workloads.exists_one(w, w.name == "hubble-enterprise" && w.kind == WORKLOAD_KIND_DAEMONSET && w.processes == [ApplicationProcessGroup{name: "/usr/local/bin/ruby"}]))`,
		`model.host.processes.exists_one(p, p.name.matches("/aws$") && p.connections.size() > 0)`,
	}
	chk, err = checker.NewApplicationModelChecker()
	require.NoError(t, err)
	res, err := chk.CheckApplicationModelEventJSON(ctx, appModelEventJSON, exprs)
	require.NoError(t, err)
	assert.True(t, res.Ok())
}
