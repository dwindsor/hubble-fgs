// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package config

import (
	"flag"
)

var __config *Opts

type Opts struct {
	EnableTetragon       bool
	PrintContainerStdout bool
	RemoveContainer      bool
}

var ConfigDefaults = Opts{
	EnableTetragon:       true,
	PrintContainerStdout: false,
	RemoveContainer:      true,
}

func Config() *Opts {
	if __config != nil {
		return __config
	}

	c := ConfigDefaults
	__config = &c

	flag.BoolVar(&__config.EnableTetragon, "enable-tetragon",
		ConfigDefaults.EnableTetragon,
		"Enable Tetragon when running the tests. Turn this off to verify that tests pass without Tetragon enabled.")

	flag.BoolVar(&__config.PrintContainerStdout, "print-stdout",
		ConfigDefaults.PrintContainerStdout,
		"Print the stdout and stderr of docker execs.")

	flag.BoolVar(&__config.RemoveContainer, "remove-container",
		ConfigDefaults.RemoveContainer,
		"Remove the docker container when tests complete. Turn this off to help debug failures.")

	return __config
}
