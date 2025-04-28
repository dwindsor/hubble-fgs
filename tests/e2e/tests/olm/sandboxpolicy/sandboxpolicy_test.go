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

package sandboxpolicy_test

import (
	"context"
	"fmt"
	"testing"

	// Fix up OSS configuration defaults.
	_ "github.com/isovalent/hubble-fgs/tests/e2e/enterprise"
	"github.com/isovalent/hubble-fgs/tests/e2e/olm"
	sandboxpolicye2e "github.com/isovalent/hubble-fgs/tests/e2e/tests/common/sandboxpolicy"

	"github.com/cilium/tetragon/tests/e2e/helpers"
	install "github.com/cilium/tetragon/tests/e2e/install/tetragon"
	"github.com/cilium/tetragon/tests/e2e/runners"

	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

// This holds our test environment which we get from calling runners.NewRunner().Setup()
var runner *runners.Runner

func TestMain(m *testing.M) {
	runner = runners.
		NewRunner().
		NoInstallCilium().
		WithInstallTetragonFn(olm.TetragonInstall(
			install.WithHelmOptions(map[string]string{
				"tetragon.exportAllowList":       "",
				"tetragon.enablePolicyFilter":    "true",
				"tetragon.enableSandboxpolicies": "true",
				"tetragon.enableCiliumAPI":       "false",
			})),
		).Init()

	runner.Setup(func(ctx context.Context, c *envconf.Config) (context.Context, error) {
		// placeholder for future functionaility
		ctx, _ = helpers.DeleteNamespace(sandboxpolicye2e.Namespace, true)(ctx, c)
		ctx, err := helpers.CreateNamespace(sandboxpolicye2e.Namespace, true)(ctx, c)
		if err != nil {
			return ctx, fmt.Errorf("failed to create namespace: %w", err)
		}
		return ctx, nil
	})

	// Run the tests using the test runner.
	runner.Run(m)
}

func TestOLMSandboxPolicy(t *testing.T) {
	sandboxpolicye2e.Test(t, runner, sandboxpolicye2e.Namespace)
}
