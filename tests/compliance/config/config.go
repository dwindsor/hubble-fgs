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
