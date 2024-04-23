//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package demoapp_test

import (
	"context"
	"fmt"
	"testing"

	// Fix up OSS configuration defaults.
	_ "github.com/isovalent/hubble-fgs/tests/e2e/enterprise"
	"github.com/isovalent/hubble-fgs/tests/e2e/olm"
	"github.com/isovalent/hubble-fgs/tests/e2e/tests/common/demoapp"

	"sigs.k8s.io/e2e-framework/pkg/envconf"

	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/install/tetragon"
	"github.com/cilium/tetragon/tests/e2e/runners"
)

var runner *runners.Runner

func TestMain(m *testing.M) {
	runner = runners.NewRunner().WithInstallTetragonFn(olm.TetragonInstall(tetragon.WithHelmOptions(map[string]string{
		"tetragon.exportAllowList":    "",
		"tetragon.enablePolicyFilter": "true",
	}))).Init()

	runner.Setup(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		// TODO: LoadCRDString, LoadCRDFile, UnloadCRDString etc are badly named
		// There is nothing specific to CRDs in their code
		// A better name may be LoadResourceString, LoadResourceFile, etc
		ctx, _ = helpers.LoadCRDString(demoapp.Namespace, demoapp.TracingPolicyYaml, true)(ctx, cfg)
		return ctx, nil
	})

	runner.Setup(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		ctx, _ = helpers.DeleteNamespace(demoapp.Namespace, true)(ctx, cfg)
		ctx, err := helpers.CreateNamespace(demoapp.Namespace, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to create demo app namespace: %w", err)
		}

		return ctx, nil
	})

	runner.Finish(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		var err error
		ctx, err = helpers.UnloadCRDString(demoapp.Namespace, demoapp.TracingPolicyYaml, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to remove tracing policy: %w", err)
		}
		return ctx, nil
	})

	runner.Finish(demoapp.UninstallDemoApp())

	runner.Run(m)
}

func TestOLMDemoApp(t *testing.T) {
	demoapp.Test(t, runner)
}
