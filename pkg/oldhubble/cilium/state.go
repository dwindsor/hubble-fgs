// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package cilium

import (
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/isovalent/hubble-fgs/pkg/oldhubble/cilium/client"
	"github.com/isovalent/hubble-fgs/pkg/oldhubble/ipcache"
	"github.com/sirupsen/logrus"
)

// State contains various caches for Cilium state and channels to notify
// state changes.
type State struct {
	// Client will connect to Cilium to pool cilium endpoint information
	ciliumClient client.Client

	// ipcache is a mirror of Cilium's IPCache
	ipcache *ipcache.IPCache

	log *logrus.Entry
}

// NewCiliumState returns a pointer to an initialized State struct.
func NewCiliumState(
	ciliumClient client.Client,
	ipCache *ipcache.IPCache,
	logger *logrus.Entry,
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
