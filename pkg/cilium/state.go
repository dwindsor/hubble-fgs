// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package cilium

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/oldhubble/cilium"
	"github.com/isovalent/hubble-fgs/pkg/oldhubble/cilium/client"
	"github.com/isovalent/hubble-fgs/pkg/oldhubble/ipcache"
)

var (
	ciliumState *cilium.State
)

func GetCiliumState() *cilium.State {
	return ciliumState
}

func InitCiliumState(ctx context.Context, enableCiliumAPI bool) (*cilium.State, error) {
	if ciliumState != nil {
		return ciliumState, nil
	}
	if !enableCiliumAPI {
		logger.GetLogger().Info("Disabling Cilium API")
		ciliumState = GetFakeCiliumState()
	} else {
		logger.GetLogger().Info("Enabling Cilium API")
		ciliumClient, err := client.NewClient()
		if err != nil {
			return nil, fmt.Errorf("failed to get Cilium client: %v", err)
		}
		ciliumState = cilium.NewCiliumState(
			ciliumClient,
			ipcache.New(),
			logger.GetLogger().With("subsystem", "cilium"))
		go HandleMonitorSocket(ctx, ciliumState)
	}
	return ciliumState, nil
}

func GetFakeCiliumState() *cilium.State {
	return cilium.NewCiliumState(
		&fakeCiliumClient{},
		ipcache.New(),
		logger.GetLogger().With("subsystem", "cilium"))
}

type fakeCiliumClient struct{}

func (f fakeCiliumClient) GetIPCache() ([]*models.IPListEntry, error) {
	return nil, nil
}
