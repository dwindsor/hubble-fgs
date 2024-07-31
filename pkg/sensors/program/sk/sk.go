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

	opts := &program.LoadOpts{
		Attach: program.RawAttach(fd),
	}
	return program.LoadProgramOpts(bpfDir, load, opts, verbose)
}
