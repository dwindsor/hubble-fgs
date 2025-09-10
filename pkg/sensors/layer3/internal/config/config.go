package layer3cfg

import (
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

var (
	confMutex sync.Mutex
)

func ConfigureSettings(enableRaw, enableRawReportClose, enableUdpReportClose bool) networkapi.ConfigValue {
	icmpTracking := uint8(0)

	if enterpriseOption.Config.EnableIcmpTracking {
		icmpTracking = 1
	}

	icmpNetMatch := uint8(1)
	if !utils.SupportCGroupSKBProbeRead() {
		icmpNetMatch = 0
	}

	rawEnabled := uint8(0)
	if enableRaw || enterpriseOption.Config.EnableRawsock {
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

	value := &networkapi.ConfigValue{
		EnableIcmpTracking: icmpTracking,
		IcmpNetMatch:       icmpNetMatch,
		RawEnabled:         rawEnabled,
		RawReportClose:     rawReportClose,
		UdpReportClose:     udpReportClose,
	}
	logger.GetLogger().Info("Config", "enableIcmpTracking", icmpTracking)
	return *value
}

func WriteSettings(value networkapi.ConfigValue) error {
	confMutex.Lock()
	defer confMutex.Unlock()
	m, err := ebpf.LoadPinnedMap(filepath.Join(bpf.MapPrefixPath(), base.CfgMap.Name), nil)
	if err != nil {
		// If no configuration map, then no configuration required!
		return nil
	}
	defer m.Close()

	key := &networkapi.ConfigKey{
		Zero: uint32(0),
	}

	err = m.Put(key, &value)
	if err != nil {
		logger.GetLogger().Warn("configureSettings couldn't update tg_l3_cfg", logfields.Error, err)
		return err
	}
	var vOut networkapi.ConfigValue
	err = m.Lookup(key, &vOut)
	if err != nil {
		logger.GetLogger().Warn("configureSettings couldn't lookup tg_l3_cfg", logfields.Error, err)
	}
	return err
}
