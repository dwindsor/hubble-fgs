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

// Package grpctls_test verifies the agent's TCP gRPC listener enforces mTLS:
// a valid client cert succeeds, plaintext and anonymous TLS clients are
// rejected. Test logic lives in the OSS tests/e2e/helpers/grpctls package.
package grpctls_test

import (
	// Fix up OSS configuration defaults.
	_ "github.com/isovalent/hubble-fgs/tests/e2e/enterprise"

	"testing"

	"github.com/cilium/tetragon/tests/e2e/helpers/grpctls"
	tetragoninstall "github.com/cilium/tetragon/tests/e2e/install/tetragon"
	"github.com/cilium/tetragon/tests/e2e/runners"
)

var runner *runners.Runner

// TestMain installs Tetragon with mTLS via the helm method. The runner's
// default plaintext auto port-forward is skipped because it would fail the
// handshake against a TLS-required listener.
func TestMain(m *testing.M) {
	runner = runners.NewRunner().
		NoPortForward().
		WithInstallTetragon(tetragoninstall.WithHelmOptions(grpctls.HelmOptions())).
		Init()
	runner.Run(m)
}

func TestMTLSHandshake(t *testing.T) {
	runner.Test(t, grpctls.HandshakeFeature(runner))
}

func TestMTLSRejectsPlaintext(t *testing.T) {
	runner.Test(t, grpctls.RejectsPlaintextFeature(runner))
}

func TestMTLSRejectsAnonymousTLS(t *testing.T) {
	runner.Test(t, grpctls.RejectsAnonymousTLSFeature(runner))
}
