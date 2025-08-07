package lpm

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
)

func NewLPM() (*LPMMap, error) {
	fileLpm4 := filepath.Join(bpf.MapPrefixPath(), Addr4lpmMapName)
	addr4lpm, err := ebpf.LoadPinnedMap(fileLpm4, nil)
	if err != nil {
		logger.GetLogger().Error(fmt.Sprintf("failed to pin addr4 LPM Map (%s)", fileLpm4), logfields.Error, err)
		return nil, err
	}

	fileLpm6 := filepath.Join(bpf.MapPrefixPath(), Addr6lpmMapName)
	addr6lpm, err := ebpf.LoadPinnedMap(fileLpm6, nil)
	if err != nil {
		logger.GetLogger().Error(fmt.Sprintf("failed to pin addr6 LPM Map (%s)", fileLpm6), logfields.Error, err)
		return nil, err
	}

	return &LPMMap{
		addr6: addr6lpm,
		addr4: addr4lpm,
	}, nil
}
