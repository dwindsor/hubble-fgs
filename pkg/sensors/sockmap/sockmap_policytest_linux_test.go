// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build sudo_tests

package sockmap_test

import (
	"testing"

	enterprisepolicytest "github.com/isovalent/hubble-fgs/pkg/testutils/policytest"
	_ "github.com/isovalent/hubble-fgs/tests/policytests"
)

func TestTLS13PT(t *testing.T) {
	enterprisepolicytest.DoObserverTest(t, "tls-13-curl-policy", map[string]any{"mode": "socket"})
}

func TestCGTLS13PT(t *testing.T) {
	enterprisepolicytest.DoObserverTest(t, "tls-13-curl-policy", map[string]any{"mode": "cgroup"})
}

func TestTLS13CLIPT(t *testing.T) {
	enterprisepolicytest.DoObserverTest(t, "tls-13-curl-no-policy-socket", nil)
}

func TestCGTLS13CLIPT(t *testing.T) {
	enterprisepolicytest.DoObserverTest(t, "tls-13-curl-no-policy-cgroup", nil)
}
