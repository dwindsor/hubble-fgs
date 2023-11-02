package exec

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/sirupsen/logrus"
)

type ConfigKey struct {
	Zero uint32
}

func (k *ConfigKey) String() string { return fmt.Sprintf("Zero: %d", k.Zero) }

type ConfigValue struct {
	EnableIcmpTracking uint8
	IcmpNetMatch       uint8
	Pad                [6]uint8
}

func (v *ConfigValue) String() string {
	return fmt.Sprintf("EnableIcmpTracking: %d", v.EnableIcmpTracking)
}

func configureSettings(enableIcmpTracking bool) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(bpf.MapPrefixPath(), base.CfgMap.Name), nil)
	if err != nil {
		return err
	}
	defer m.Close()

	key := &ConfigKey{
		Zero: uint32(0),
	}
	icmpTracking := uint8(0)

	if enableIcmpTracking {
		icmpTracking = 1
	}

	icmpNetMatch := uint8(1)
	if v := "5.10.0"; !kernels.MinKernelVersion(v) {
		icmpNetMatch = 0
	}

	value := &ConfigValue{
		EnableIcmpTracking: icmpTracking,
		IcmpNetMatch:       icmpNetMatch,
	}
	m.Put(key, value)
	logger.GetLogger().WithFields(logrus.Fields{"enableIcmpTracking": icmpTracking}).Info("Config:")
	return nil
}
