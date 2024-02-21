package sk

import (
	"github.com/cilium/tetragon/pkg/sensors/program"
)

func LoadSkProgram(
	bpfDir string,
	load *program.Program,
	sockmap *program.Map,
	verbose int,
) error {

	fd, err := sockmap.GetFD()
	if err != nil {
		return err
	}

	return program.LoadProgram(bpfDir, load, program.RawAttach(fd), verbose)
}
