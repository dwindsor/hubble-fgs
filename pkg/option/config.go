// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

type config struct {
	EnableProcessAncestors bool
}

var (
	// Config contains all the configuration used by Tetragon.
	Config = config{
		EnableProcessAncestors: false,
	}
)
