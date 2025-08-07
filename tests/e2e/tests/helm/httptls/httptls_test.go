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

package httptls_test

import (
	// Fix up OSS configuration defaults.
	"os"

	"context"
	"fmt"
	"testing"

	_ "github.com/isovalent/hubble-fgs/tests/e2e/enterprise"
	"github.com/isovalent/hubble-fgs/tests/e2e/tests/common/httptls"

	"sigs.k8s.io/e2e-framework/pkg/envconf"

	"github.com/cilium/tetragon/tests/e2e/helpers"
	install "github.com/cilium/tetragon/tests/e2e/install/tetragon"
	"github.com/cilium/tetragon/tests/e2e/runners"
)

var runner *runners.Runner

func TestMain(m *testing.M) {
	if os.Getenv("FLAKY_HTTP") != "" {
		return
	}

	runner = runners.NewRunner().WithInstallTetragon(install.WithHelmOptions(map[string]string{
		"enterprise.exportAllowList": "",
		"tetragon.enableCiliumAPI":   "false",
		"enterprise.enableTLSEvents": "true",
	})).Init()

	runner.Setup(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		var err error
		ctx, _ = helpers.DeleteNamespace(httptls.Namespace, true)(ctx, cfg)
		ctx, err = helpers.CreateNamespace(httptls.Namespace, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to create curl namespace: %w", err)
		}
		ctx, err = helpers.LoadCRDString(httptls.Namespace, httptls.CURLYAML, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to deploy curl pod: %w", err)
		}
		return ctx, nil
	})

	runner.Setup(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		ctx, _ = helpers.LoadCRDString(httptls.Namespace, httptls.TracingPolicyYAML, true)(ctx, cfg)
		return ctx, nil
	})

	runner.Finish(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		var err error
		ctx, err = helpers.UnloadCRDString(httptls.Namespace, httptls.TracingPolicyYAML, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to remove tracing policy: %w", err)
		}
		return ctx, nil
	})

	runner.Finish(func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		var err error
		ctx, err = helpers.UnloadCRDString(httptls.Namespace, httptls.CURLYAML, true)(ctx, cfg)
		if err != nil {
			return ctx, fmt.Errorf("failed to remove tracing policy: %w", err)
		}
		return ctx, nil
	})

	runner.Run(m)
}

func TestHTTP(t *testing.T) {
	httptls.TestHTTP(t, runner)
}

func TestTLS(t *testing.T) {
	t.Skipf("TLS tests are currently disabled due to CI flakes. See GitHub Issue: https://github.com/isovalent/hubble-fgs/issues/6288")
	httptls.TestTLS(t, runner)
}
