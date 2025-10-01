// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package defaults

import "github.com/cilium/tetragon/pkg/defaults"

const (
	// Default directory from where to load any type of policy.
	DefaultPoliciesDir = defaults.DefaultRunDir + "tetragon.policies.d"
)
