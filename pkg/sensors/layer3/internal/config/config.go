package layer3cfg

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

func ConfigureSettings(enableRaw, enableRawReportClose, enableUdpReportClose bool) networkapi.Layer3ConfigValue {
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

	value := &networkapi.Layer3ConfigValue{
		EnableIcmpTracking: icmpTracking,
		IcmpNetMatch:       icmpNetMatch,
		RawEnabled:         rawEnabled,
		RawReportClose:     rawReportClose,
		UdpReportClose:     udpReportClose,
	}
	return *value
}

// UpdateMap flushes all the values from the config struct to the BPF map
func UpdateMap(value networkapi.Layer3ConfigValue) error {
	configMapFile := filepath.Join(bpf.MapPrefixPath(), base.CfgMap.Name)
	m, err := ebpf.LoadPinnedMap(configMapFile, nil)
	if err != nil {
		return fmt.Errorf("failed to load the config map %s: %w", configMapFile, err)
	}
	defer m.Close()

	zero := uint32(0)
	err = m.Put(&zero, &value)
	if err != nil {
		return fmt.Errorf("failed to put value into the layer3 config map: %w", err)
	}

	return nil
}
