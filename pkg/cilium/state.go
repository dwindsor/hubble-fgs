// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
