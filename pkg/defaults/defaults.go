// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package defaults

const (
	// Default directory from where to load any type of policy.
	DefaultPoliciesDir = "/etc/tetragon/tetragon.policies.d"
)
