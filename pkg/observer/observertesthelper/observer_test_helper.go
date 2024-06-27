//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package observertesthelper

//revive:disable:context-as-argument

import (
	"context"
	"sync"
	"testing"

	"github.com/cilium/tetragon/pkg/metricsconfig"
	"github.com/cilium/tetragon/pkg/observer"
	oss "github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/cilium"
	enterpriseMetricsConfig "github.com/isovalent/hubble-fgs/pkg/metricsconfig"
)

var (
	enterpriseOnce sync.Once
)

func enterpriseInit() {
	enterpriseOnce.Do(func() {
		enterpriseMetricsConfig.InitAllEEMetrics(metricsconfig.GetRegistry())
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
