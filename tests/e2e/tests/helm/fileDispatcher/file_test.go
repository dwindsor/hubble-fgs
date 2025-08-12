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

//go:build e2e_tests

package fileDispatcher_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	// Fix up OSS configuration defaults.
	"sigs.k8s.io/e2e-framework/pkg/envconf"

	_ "github.com/isovalent/hubble-fgs/tests/e2e/enterprise"
	"github.com/isovalent/hubble-fgs/tests/e2e/tests/common/fileDispatcher"

	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/helpers/grpc"
	install "github.com/cilium/tetragon/tests/e2e/install/tetragon"
	"github.com/cilium/tetragon/tests/e2e/runners"
)

var runner *runners.Runner

func TestMain(m *testing.M) {
	if os.Getenv("RUN_FIM_DISPATCHER") != "1" {
		return
	}

	runner = runners.NewRunner().WithInstallTetragon(install.WithHelmOptions(map[string]string{
		"tetragon.exportAllowList":             "",
		"tetragon.enableCiliumAPI":             "false",
		"tetragon.enablePolicyFilter":          "true",
		"tetragon.enablePolicyFilterCgroupMap": "true",
		"tetragon.fimDispatcher.enabled":       "true",
	})).Init()

	runner.Setup(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		var err error
		ctx, _ = helpers.DeleteNamespace(fileDispatcher.Namespace, true)(ctx, cfg)
		ctx, err = helpers.CreateNamespace(fileDispatcher.Namespace, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to create file namespace: %w", err)
		}
		ctx, err = helpers.LoadCRDString(fileDispatcher.Namespace, fileDispatcher.UbuntulDefaultYaml, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to deploy ubuntu pod: %w", err)
		}
		return ctx, nil
	})

	runner.Setup(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		ctx, err := helpers.LoadCRDString("default", fileDispatcher.PolicyPrefixYaml, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to load PolicyPrefixYaml: %w", err)
		}
		if err := grpc.WaitForTracingPolicyWithTime(ctx, "fim-prefix", 20, 3*time.Second); err != nil {

			return ctx, err
		}
		return ctx, nil
	})

	runner.Setup(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		ctx, err := helpers.LoadCRDString("default", fileDispatcher.PolicySuffixYaml, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to load PolicySuffixYaml: %w", err)
		}
		if err := grpc.WaitForTracingPolicyWithTime(ctx, "fim-suffix", 20, 3*time.Second); err != nil {

			return ctx, err
		}
		return ctx, nil
	})

	runner.Finish(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		ctx, err := helpers.UnloadCRDString("default", fileDispatcher.PolicySuffixYaml, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to remove PolicySuffixYaml: %w", err)
		}
		return ctx, nil
	})

	runner.Finish(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		ctx, err := helpers.UnloadCRDString("default", fileDispatcher.PolicyPrefixYaml, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to remove PolicyPrefixYaml: %w", err)
		}
		return ctx, nil
	})

	runner.Finish(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		ctx, err := helpers.UnloadCRDString(fileDispatcher.Namespace, fileDispatcher.UbuntulDefaultYaml, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to remove ubuntu pod: %w", err)
		}
		return ctx, nil
	})

	runner.Run(m)
}

func TestFile(t *testing.T) {
	fileDispatcher.Test(t, runner)
}
