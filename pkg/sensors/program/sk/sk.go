package sk

import (
	"github.com/cilium/tetragon/pkg/sensors/program"
)

func LoadSkProgram(
	bpfDir, mapDir string,
	load *program.Program,
	sockmap *program.Map,
) error {

	fd, err := sockmap.GetFD()
	if err != nil {
		return err
	}

	return program.LoadProgram(bpfDir, []string{mapDir}, load, program.RawAttach(fd))
}
