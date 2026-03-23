// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build e2e_tests

package file_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	// Fix up OSS configuration defaults.
	_ "github.com/isovalent/hubble-fgs/tests/e2e/enterprise"
	"github.com/isovalent/hubble-fgs/tests/e2e/tests/common/file"

	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/pkg/envconf"

	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/helpers/grpc"
	install "github.com/cilium/tetragon/tests/e2e/install/tetragon"
	"github.com/cilium/tetragon/tests/e2e/runners"
)

var runner *runners.Runner
var supportEnforcement = false

func TestMain(m *testing.M) {
	if os.Getenv("FLAKY_FIM") != "" {
		return
	}

	runner = runners.NewRunner().WithInstallTetragon(install.WithHelmOptions(map[string]string{
		"tetragon.exportAllowList":    "",
		"tetragon.enableCiliumAPI":    "false",
		"tetragon.enablePolicyFilter": "true",
	})).Init()

	runner.Setup(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		var err error
		ctx, _ = helpers.DeleteNamespace(file.Namespace, true)(ctx, cfg)
		ctx, err = helpers.CreateNamespace(file.Namespace, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to create file namespace: %w", err)
		}
		pr := os.Getenv("HOST_PROC")
		if pr == "" {
			pr = "/proc"
		}
		ctx, err = helpers.LoadCRDString(file.Namespace, strings.ReplaceAll(file.UbuntulYaml, "HOST_PROC", pr), true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to deploy ubuntu pod: %w", err)
		}
		return ctx, nil
	})

	runner.Setup(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		ctx, err := helpers.LoadCRDString("default", file.UbuntulDefaultYaml, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to deploy ubuntu pod: %w", err)
		}
		return ctx, nil
	})

	runner.Setup(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		ctx, err := helpers.LoadCRDString(file.Namespace, file.TracingPolicyYaml, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to load tracingPolicyYaml: %w", err)
		}
		if err := grpc.WaitForTracingPolicyWithTime(ctx, "file-monitoring", 20, 3*time.Second); err != nil {
			return ctx, err
		}
		return ctx, nil
	})

	runner.Setup(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		ctx, err := helpers.LoadCRDString("default", file.TracingPolicyNamespacedYaml, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to load tracingPolicyNamespacedYaml: %w", err)
		}
		if err := grpc.WaitForTracingPolicyWithTime(ctx, "file-monitoring-namespaced", 20, 3*time.Second); err != nil {
			return ctx, err
		}
		return ctx, nil
	})

	runner.Setup(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		client, err := cfg.NewClient()
		if err != nil {
			klog.Info("Failed to get client")
			return ctx, nil
		}

		supportEnforcement, err = file.TestFileEnforcement(ctx, client)
		if err != nil {
			klog.Infof("Failed to run testFileEnforcement [%s]", err)
			return ctx, nil
		}

		if supportEnforcement {
			klog.Info("Kernel supports file enforcement")
			ctx, err := helpers.LoadCRDString(file.Namespace, file.TracingEnforcePolicyYaml, true)(ctx, cfg)
			if err != nil {
				return ctx, fmt.Errorf("failed to load tracingEnforcePolicyYaml: %w", err)
			}
			if err := grpc.WaitForTracingPolicyWithTime(ctx, "file-monitoring-enforcement", 20, 3*time.Second); err != nil {
				return ctx, err
			}
		} else {
			klog.Info("Kernel does not support file enforcement")
		}
		return ctx, nil
	})

	runner.Finish(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		if supportEnforcement {
			var err error
			ctx, err = helpers.UnloadCRDString(file.Namespace, file.TracingEnforcePolicyYaml, true)(ctx, cfg)
			if err != nil {
				return ctx, fmt.Errorf("failed to remove tracing policy: %w", err)
			}
		}
		return ctx, nil
	})

	runner.Finish(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		var err error
		ctx, err = helpers.UnloadCRDString(file.Namespace, file.TracingPolicyYaml, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to remove tracing policy: %w", err)
		}
		return ctx, nil
	})

	runner.Finish(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		ctx, err := helpers.UnloadCRDString("default", file.TracingPolicyNamespacedYaml, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to remove tracing policy: %w", err)
		}
		return ctx, nil
	})

	runner.Finish(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		pr := os.Getenv("HOST_PROC")
		if pr == "" {
			pr = "/proc"
		}
		var err error
		ctx, err = helpers.UnloadCRDString(file.Namespace, strings.ReplaceAll(file.UbuntulYaml, "HOST_PROC", pr), true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to remove tracing policy: %w", err)
		}
		return ctx, nil
	})

	runner.Finish(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		ctx, err := helpers.UnloadCRDString("default", file.UbuntulDefaultYaml, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to remove tracing policy: %w", err)
		}
		return ctx, nil
	})

	runner.Run(m)
}

func TestFile(t *testing.T) {
	file.Test(t, runner, supportEnforcement)
}
