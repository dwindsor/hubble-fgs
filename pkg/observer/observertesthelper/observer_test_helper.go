// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !windows

package observertesthelper

//revive:disable:context-as-argument

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/metricsconfig"
	"github.com/cilium/tetragon/pkg/observer"
	oss "github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"

	"github.com/isovalent/hubble-fgs/pkg/cilium"
	enterpriseMetricsConfig "github.com/isovalent/hubble-fgs/pkg/metricsconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
)

const (
	testConfigFile = "/tmp/hubble-tetragon.gotest.yaml"

	EmptyTracingPolicy = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "noconfig"
spec: {}
`
)

var (
	enterpriseOnce sync.Once
)

func enterpriseInit() {
	enterpriseOnce.Do(func() {
		enterpriseMetricsConfig.InitAllEEHealthMetrics(metricsconfig.GetRegistry())
		enterpriseMetricsConfig.InitAllEEEventMetrics(metricsconfig.GetRegistry())
		cilium.InitCiliumState(context.Background(), false)
	})
}

func GetDefaultObserver(tb testing.TB, ctx context.Context, lib string, opts ...oss.TestOption) (*observer.Observer, error) {
	obs, err := oss.GetDefaultObserver(tb, ctx, lib, opts...)
	if err != nil {
		return nil, err
	}
	enterpriseInit()
	return obs, nil
}

func GetDefaultObserverWithWatchers(tb testing.TB, ctx context.Context, base *sensors.Sensor, opts ...oss.TestOption) (*observer.Observer, error) {
	obs, err := oss.GetDefaultObserverWithWatchers(tb, ctx, base, opts...)
	if err != nil {
		return nil, err
	}
	enterpriseInit()
	return obs, nil
}

func GetDefaultObserverWithBase(tb testing.TB, ctx context.Context, b *sensors.Sensor, file, lib string, opts ...oss.TestOption) (*observer.Observer, error) {
	obs, err := oss.GetDefaultObserverWithBase(tb, ctx, b, file, lib, opts...)
	if err != nil {
		return nil, err
	}
	enterpriseInit()
	return obs, nil
}

func GetDefaultObserverWithFile(tb testing.TB, ctx context.Context, file, lib string, opts ...oss.TestOption) (*observer.Observer, error) {
	obs, err := oss.GetDefaultObserverWithFile(tb, ctx, file, lib, opts...)
	if err != nil {
		return nil, err
	}
	enterpriseInit()
	return obs, nil
}

func GetDefaultObserverWithConfig(tb testing.TB, ctx context.Context, config, lib string, opts ...oss.TestOption) (*observer.Observer, error) {
	obs, err := oss.GetDefaultObserverWithConfig(tb, ctx, config, lib, opts...)
	if err != nil {
		return nil, err
	}
	enterpriseInit()
	return obs, nil
}

// NB(kkourt): Function(t *testing.T, ctx context.Context) is the reasonable
// thing to do here even if revive complains.
func GetNoConfigObserver(t *testing.T, ctx context.Context, filtered bool) *observer.Observer { //nolint:revive
	if err := oss.WriteConfigFile(testConfigFile, EmptyTracingPolicy); err != nil {
		t.Fatalf("WriteFile(%s): err %s", testConfigFile, err)
	}

	base := base.GetInitialSensorTest(t)
	var obs *observer.Observer
	var err error
	if filtered {
		obs, err = GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib, oss.WithMyPid())
	} else {
		obs, err = GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib)
	}
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	err = confmap.UpdateTgRuntimeConf(bpf.MapPrefixPath(), os.Getpid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	return obs
}
