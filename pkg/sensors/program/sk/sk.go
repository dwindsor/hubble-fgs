package sk

import (
	"github.com/cilium/tetragon/pkg/sensors/program"
)

type tailCall struct {
	name   string
	prefix string
}

func LoadSkProgram(
	bpfDir string,
	load *program.Program,
	sockmap *program.Map,
	tailmap *program.Map,
	verbose int,
) error {

	fd, err := sockmap.GetFD()
	if err != nil {
		return err
	}

	var tc tailCall
	if tailmap != nil {
		if tailmap.Name == "http1_calls" {
			tc = tailCall{tailmap.Name, "sk_msg"}
		}
		if tailmap.Name == "http1_calls_skb" {
			tc = tailCall{tailmap.Name, "sk_skb/stream_verdict"}
		}
	}

	opts := &program.LoadOpts{
		Attach:   program.RawAttach(fd),
		TcMap:    tc.name,
		TcPrefix: tc.prefix,
	}
	return program.LoadProgramOpts(bpfDir, load, opts, verbose)
}
