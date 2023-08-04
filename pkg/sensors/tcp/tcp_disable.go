package tcp

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/sirupsen/logrus"
)

type EventDisableKey struct {
	Zero uint32
}

func (k *EventDisableKey) String() string { return fmt.Sprintf("Zero: %d", k.Zero) }

type EventDisableValue struct {
	DisableConnect uint8
	DisableClose   uint8
	DisableAccept  uint8
	DisableListen  uint8
}

func (v *EventDisableValue) String() string {
	return fmt.Sprintf("DisableConnect: %d, "+
		"DisableClose: %d "+
		"DisableAccept: %d, "+
		"DisableListen: %d, ",
		v.DisableConnect, v.DisableClose, v.DisableAccept, v.DisableListen)
}

func configureTCPDisableEvents(disableConnect bool, disableClose bool, disableAccept bool, disableListen bool) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(bpf.MapPrefixPath(), EventDisableConfig.Name), nil)
	if err != nil {
		return err
	}
	defer m.Close()

	key := &EventDisableKey{
		Zero: uint32(0),
	}
	disableConnectVar := uint8(0)
	disableCloseVar := uint8(0)
	disableAcceptVar := uint8(0)
	disableListenVar := uint8(0)

	if disableConnect {
		disableConnectVar = 1
	}
	if disableClose {
		disableCloseVar = 1
	}
	if disableAccept {
		disableAcceptVar = 1
	}
	if disableListen {
		disableListenVar = 1
	}

	value := &EventDisableValue{
		DisableConnect: disableConnectVar,
		DisableClose:   disableCloseVar,
		DisableAccept:  disableAcceptVar,
		DisableListen:  disableListenVar,
	}
	m.Put(key, value)
	logger.GetLogger().WithFields(logrus.Fields{"disableConnect": disableConnectVar,
		"disableClose":  disableCloseVar,
		"disableAccept": disableAcceptVar,
		"disableListen": disableListenVar}).Info("Event config:")
	return nil
}
