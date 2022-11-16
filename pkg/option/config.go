// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

type config struct {
	EnableProcessAncestors bool
	ProtocolShift          int
}

const (
	ShiftFalse = iota
	ShiftTrue
	ShiftAuto
)

var (
	// Config contains all the configuration used by Tetragon.
	Config = config{
		EnableProcessAncestors: false,
		ProtocolShift:          ShiftAuto,
	}
)
