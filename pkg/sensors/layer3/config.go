package layer3

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

var (
	confMutex sync.Mutex
)

type ConfigKey struct {
	Zero uint32
}

func (k *ConfigKey) String() string { return fmt.Sprintf("Zero: %d", k.Zero) }

type ConfigValue struct {
	EnableIcmpTracking uint8
	IcmpNetMatch       uint8
	RawEnabled         uint8
	RawReportClose     uint8
	UdpReportClose     uint8
	Pad                [3]uint8
}

func (v *ConfigValue) String() string {
	return fmt.Sprintf("EnableIcmpTracking: %d", v.EnableIcmpTracking)
}

func configureSettings(enableRaw, enableRawReportClose, enableUdpReportClose bool) ConfigValue {
	icmpTracking := uint8(0)

	if enterpriseOption.Config.EnableIcmpTracking {
		icmpTracking = 1
	}

	icmpNetMatch := uint8(1)
	if !utils.SupportCGroupSKBProbeRead() {
		icmpNetMatch = 0
	}

	rawEnabled := uint8(0)
	if enableRaw {
		rawEnabled = 1
	}

	rawReportClose := uint8(0)
	if enableRawReportClose {
		rawReportClose = 1
	}

	udpReportClose := uint8(0)
	if enableUdpReportClose {
		udpReportClose = 1
	}

	value := &ConfigValue{
		EnableIcmpTracking: icmpTracking,
		IcmpNetMatch:       icmpNetMatch,
		RawEnabled:         rawEnabled,
		RawReportClose:     rawReportClose,
		UdpReportClose:     udpReportClose,
	}
	logger.GetLogger().Info("Config", "enableIcmpTracking", icmpTracking)
	return *value
}

func writeSettings(value ConfigValue) error {
	confMutex.Lock()
	defer confMutex.Unlock()
	m, err := ebpf.LoadPinnedMap(filepath.Join(bpf.MapPrefixPath(), base.CfgMap.Name), nil)
	if err != nil {
		// If no configuration map, then no configuration required!
		return nil
	}
	defer m.Close()

	key := &ConfigKey{
		Zero: uint32(0),
	}

	err = m.Put(key, &value)
	if err != nil {
		logger.GetLogger().Warn("configureSettings couldn't update tg_l3_cfg", logfields.Error, err)
		return err
	}
	var vOut ConfigValue
	err = m.Lookup(key, &vOut)
	if err != nil {
		logger.GetLogger().Warn("configureSettings couldn't lookup tg_l3_cfg", logfields.Error, err)
	}
	return err
}
