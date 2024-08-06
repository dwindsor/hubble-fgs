//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tcpCache

import (
	"fmt"
	"sync"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/timer"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
)

const (
	// How often we check for expired tuples.
	tupleGcInterval = time.Duration(time.Second * 2)
	// How old an expired tuple needs to be for it to be deleted.
	tupleGcExpiry = time.Duration(time.Second * 10)
)

var (
	// Do not use directly, should be accessed via GetCache()
	__cache *TcpLru
	// Garbage collector to remove expired entries in the cache.
	tupleGc = timer.NewPeriodicTimer("TCP Tuple GC Timer", runTcpTupleGC, true)
	// Garbage collection list.
	expiredTuples []expiredTuple
	expiredLock   sync.Mutex
)

type TcpLru = lru.Cache[networkapi.MsgSocketId, *networkapi.MsgIPTuple]

type expiredTuple struct {
	expired time.Time
	cookie  uint64
	version uint64
}

// Return a reference to the tlsCache, allocating it first if necessary.
func GetCache() (*TcpLru, error) {
	if __cache != nil {
		return __cache, nil
	}

	logger.GetLogger().WithField("size", enterpriseOption.Config.TcpCacheSize).Info("Initializing TCP cache")
	lru, err := lru.New[networkapi.MsgSocketId, *networkapi.MsgIPTuple](enterpriseOption.Config.TcpCacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to get TCP cache: %w", err)
	}

	__cache = lru
	return __cache, nil
}

// Return the tuple for a socket
func GetTuple(cookie uint64, version uint64) *networkapi.MsgIPTuple {
	// Retrieve TCP tuple from the cache.
	tcpTuples, err := GetCache()
	if err != nil {
		return &networkapi.MsgIPTuple{}
	}
	socketId := networkapi.MsgSocketId{
		Cookie:  cookie,
		Version: version,
	}
	tuple, ok := tcpTuples.Get(socketId)
	if ok {
		return tuple
	}
	return &networkapi.MsgIPTuple{}
}

func RemoveTuple(cookie uint64, version uint64) {
	expiredLock.Lock()
	defer expiredLock.Unlock()
	expiredTuples = append(expiredTuples, expiredTuple{
		expired: time.Now(),
		cookie:  cookie,
		version: version,
	})
}

func StartGc() {
	tupleGc.Start(tupleGcInterval)
}

// Remove expired tuples
func runTcpTupleGC() {
	expiredLock.Lock()
	defer expiredLock.Unlock()
	tcpTuples, err := GetCache()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("TCP tuple GC: failed to get cache")
		return
	}
	deleteLast := -1
	for i, e := range expiredTuples {
		if e.expired.Add(tupleGcExpiry).Before(time.Now()) {
			// We have found an entry that is older than the expiry period.
			// Delete it.
			socketId := networkapi.MsgSocketId{
				Cookie:  e.cookie,
				Version: e.version,
			}
			tcpTuples.Remove(socketId)
			deleteLast = i
		} else {
			// We don't need to traverse any more as they must all be newer than the expiry interval.
			break
		}
	}
	// We have removed all the expired entries from the cache.
	// Now remove them from the expired list.
	expiredTuples = expiredTuples[deleteLast+1:]
}

func StopGc() {
	tupleGc.Stop()
}
