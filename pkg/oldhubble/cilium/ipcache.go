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
	"encoding/json"
	"time"

	"github.com/cilium/cilium/pkg/identity"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/tetragon/pkg/logger/logfields"
)

const (
	ipcacheInitRetryInterval = 5 * time.Second
	ipcacheRefreshInterval   = 5 * time.Minute
)

// fetchIPCache copies over the IP cache from cilium agent
func (s *State) fetchIPCache() error {
	entries, err := s.ciliumClient.GetIPCache()
	if err != nil {
		return err
	}
	err = s.ipcache.InitializeFrom(entries)
	if err != nil {
		return err
	}
	s.log.Debug("Fetched ipcache from cilium", "entries", len(entries))
	return nil
}

// processIPCacheEvent decodes and applies an IPCache update, returns true if
// it was applied to the local IPCache mirror.
func (s *State) processIPCacheEvent(an monitorAPI.AgentNotify) bool {
	n := monitorAPI.IPCacheNotification{}
	err := json.Unmarshal([]byte(an.Text), &n)
	if err != nil {
		s.log.Error("Unable to unmarshal IPCacheNotification",
			"type", int(an.Type),
			"IPCacheNotification", an.Text)
		return false
	}

	switch an.Type {
	case monitorAPI.AgentNotifyIPCacheUpserted:
		newID := identity.NumericIdentity(n.Identity)
		var oldID *identity.NumericIdentity
		if n.OldIdentity != nil {
			id := identity.NumericIdentity(*n.OldIdentity)
			oldID = &id
		}

		return s.ipcache.UpsertChecked(n.CIDR, newID, oldID, n.HostIP, n.OldHostIP,
			n.EncryptKey, n.Namespace, n.PodName)
	case monitorAPI.AgentNotifyIPCacheDeleted:
		return s.ipcache.Delete(n.CIDR)
	default:
		s.log.Warn("Received unknown IPCache notification type", "type", int(an.Type))
	}

	return false
}

// syncIPCache initializes the IPCache by fetching an initial version from
// Cilium and then starts reading IPCacheNotification from the channel.
func (s *State) syncIPCache(ipcacheEvents <-chan monitorAPI.AgentNotify) {
	for {
		err := s.fetchIPCache()
		if err != nil {
			s.log.Error("Failed to fetch IPCache from Cilium", logfields.Error, err)
			time.Sleep(ipcacheInitRetryInterval)
			continue
		}

		break
	}

	refresh := time.NewTimer(ipcacheRefreshInterval)
	inSync := false

	for ipcacheEvents != nil {
		select {
		case <-refresh.C:
			err := s.fetchIPCache()
			if err != nil {
				s.log.Error("Failed to fetch IPCache from Cilium", logfields.Error, err)
				refresh.Reset(ipcacheInitRetryInterval)
				continue
			}
			refresh.Reset(ipcacheRefreshInterval)
		case an, ok := <-ipcacheEvents:
			if !ok {
				return
			}
			// Initially we might see stale updates that were enqued before we
			// initialized the ipcache. Once we see the first applicable update
			// though, all subsequent updates must be applicable as well.
			updated := s.processIPCacheEvent(an)
			switch {
			case !updated && !inSync:
				s.log.Debug("Received stale ipcache update", "type", int(an.Type), "IPCacheNotification", an.Text)
			case !updated && inSync:
				s.log.Warn("Received unapplicable ipcache update", "type", int(an.Type), "IPCacheNotification", an.Text)
			case updated && !inSync:
				inSync = true
			}
		}
	}
}
