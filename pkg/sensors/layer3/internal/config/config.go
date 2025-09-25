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

func SetConfig(config *networkapi.Layer3ConfigValue, enableRaw, enableRawReportClose, enableUdpReportClose bool) {
	if enterpriseOption.Config.EnableIcmpTracking {
		config.EnableIcmpTracking = 1
	}

	if utils.SupportCGroupSKBProbeRead() {
		config.IcmpNetMatch = 1
	}

	if enableRaw || enterpriseOption.Config.EnableRawsock {
		config.RawEnabled = 1
	}

	if enableRawReportClose {
		config.RawReportClose = 1
	}

	if enableUdpReportClose {
		config.UdpReportClose = 1
	}
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
