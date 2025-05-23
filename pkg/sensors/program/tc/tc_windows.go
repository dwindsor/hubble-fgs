package tc

import (
	"github.com/cilium/tetragon/pkg/constants"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

func LoadTC(
	bpfDir string,
	load *program.Program,
	maps []*program.Map,
	verbose int,
	interfaces []string,
	attached map[NamespaceInterface]bool,
) (map[NamespaceInterface]bool, error) {
	return nil, constants.ErrWindowsNotSupported
}
