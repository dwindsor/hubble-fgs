//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tcp

import (
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
)

func ConfigureTCPDisableEvents(cfg *networkapi.Layer3ConfigValue, disableConnect bool, disableClose bool, disableAccept bool, disableListen bool) {
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

	cfg.TCPDisable = networkapi.TCPEventDisableValue{
		DisableConnect: disableConnectVar,
		DisableClose:   disableCloseVar,
		DisableAccept:  disableAcceptVar,
		DisableListen:  disableListenVar,
	}
	logger.GetLogger().Info("Event config:",
		"disableConnect", disableConnectVar,
		"disableClose", disableCloseVar,
		"disableAccept", disableAcceptVar,
		"disableListen", disableListenVar)
}
