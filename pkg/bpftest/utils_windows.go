// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bpftest

import (
	"context"
	"os"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/exec/procevents"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/stretchr/testify/require"
)

// StartMinimalTetragonModel configures and start a minimal testing tetragon
// instance to run with the application model, the DNS parser (and thus UDP),
// and TCP. This is for example the minimum configuration for network policies.
func StartMinimalTetragonModel(ctx context.Context, t *testing.T) {
	bpf.ConfigureResourceLimits()
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountTraceFS()
	bpf.CheckOrMountCgroup2()

	option.Config.HubbleLib = "../../../bpf/objs"
	option.Config.BpfDir = bpf.MapPrefixPath()
	t.Cleanup(func() {
		err := os.RemoveAll(bpf.MapPrefixPath())
		require.NoError(t, err)
	})

	enterpriseOption.Config.Layer3CLIEnable = true
	enterpriseOption.Config.EnableTCP = true
	enterpriseOption.Config.EnableUDP = true
	enterpriseOption.Config.EnableBPFDNSParser = true
	enterpriseOption.Config.EnableApplicationModel = true
	option.Config.EnablePolicyFilter = false

	obs := observer.NewObserver()
	err := obs.InitSensorManager()
	require.NoError(t, err)
	require.NoError(t, err)
	t.Cleanup(func() {
		observer.RemoveSensors(ctx)
		observer.ResetSensorManager()
	})
	baseSensor := base.GetInitialSensorTest(t)
	err = baseSensor.Load(option.Config.BpfDir)
	require.NoError(t, err)
	err = procevents.GetRunningProcs()
	require.NoError(t, err)
	err = layer3.LoadWinTCPSensor(ctx)
	require.NoError(t, err)
}
