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
	"log/slog"

	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"

	"github.com/isovalent/hubble-fgs/pkg/oldhubble/cilium/client"
	"github.com/isovalent/hubble-fgs/pkg/oldhubble/ipcache"
)

// State contains various caches for Cilium state and channels to notify
// state changes.
type State struct {
	// Client will connect to Cilium to pool cilium endpoint information
	ciliumClient client.Client

	// ipcache is a mirror of Cilium's IPCache
	ipcache *ipcache.IPCache

	log *slog.Logger
}

// NewCiliumState returns a pointer to an initialized State struct.
func NewCiliumState(
	ciliumClient client.Client,
	ipCache *ipcache.IPCache,
	logger *slog.Logger,
) *State {
	return &State{
		ciliumClient: ciliumClient,
		ipcache:      ipCache,
		log:          logger,
	}
}

// StartMirroringIPCache will obtain an initial IPCache snapshot from Cilium
// and then start mirroring IPCache events based on IPCacheNotification sent
// through the ipCacheEvents channels. Only messages of type
// `AgentNotifyIPCacheUpserted` and `AgentNotifyIPCacheDeleted` should be sent
// through that channel. This function assumes that the caller is already
// connected to Cilium Monitor, i.e. no IPCacheNotification must be lost after
// calling this method.
func (s *State) StartMirroringIPCache(ipCacheEvents <-chan monitorAPI.AgentNotify) {
	go s.syncIPCache(ipCacheEvents)
}

// GetCiliumClient returns ciliumClient.
func (s *State) GetCiliumClient() client.Client {
	return s.ciliumClient
}

// GetIPCache returns ipcache.
func (s *State) GetIPCache() *ipcache.IPCache {
	return s.ipcache
}
