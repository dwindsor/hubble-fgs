//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//
package grpc

import (
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/metrics"
	lru "github.com/hashicorp/golang-lru"
	"github.com/sirupsen/logrus"
)

type processCache struct {
	log        logrus.FieldLogger
	cache      *lru.Cache
	deleteChan chan *processInternal

	// pidMap is a map from PID to the most recent exec ID for the PID. This is used to find the parent
	// of exec events without clone flag.
	pidMap *lru.Cache
}

// garbage collection states
const (
	inUse = iota
	deletePending
	deleteReady
	deleted
)

// garbage collection run interval
const (
	intervalGC = time.Second * 30
	colorsGC   = 2
)

// processInternal is the internal representation of a process.
type processInternal struct {
	// externally visible process struct.
	process *fgs.Process
	// additional internal fields below
	capabilities *fgs.Capabilities
	// garbage collector metadata
	color int
}

func (pc *processCache) cacheGarbageCollector() {
	ticker := time.NewTicker(intervalGC)
	pc.deleteChan = make(chan *processInternal)

	go func() {
		var deleteQueue, newQueue []*processInternal

		for {
			select {
			case <-ticker.C:
				newQueue = newQueue[:0]
				for _, p := range deleteQueue {
					/* If the ref != 0 this means we have bounced
					 * through !refcnt and now have a refcnt. This
					 * can happen if we receive the following,
					 *
					 *     execve->close->connect
					 *
					 * where the connect/close sequence is received
					 * OOO. So bounce the process from the remove list
					 * and continue. If the refcnt hits zero while we
					 * are here the channel will serialize it and we
					 * will handle normally. There is some risk that
					 * we skip 2 color bands if it just hit zero and
					 * then we run ticker event before the delete
					 * channel. We could use a bit of color to avoid
					 * later if we care. Also we may try to delete the
					 * process a second time, but that is harmless.
					 */
					ref := atomic.LoadUint32(&p.process.Refcnt)
					if ref != 0 {
						continue
					}
					if p.color == deleteReady {
						p.color = deleted
						pc.remove(p.process)
					} else {
						newQueue = append(newQueue, p)
						p.color = deleteReady
					}
				}
				deleteQueue = newQueue
			case p := <-pc.deleteChan:
				// duplicate deletes can happen, if they do reset
				// color to pending and move along. This will cause
				// the GC to keep it alive for at least another pass.
				// Notice color is only ever touched inside GC behind
				// select channel logic so should be safe to work on
				// and assume its visible everywhere.
				if p.color != inUse {
					p.color = deletePending
					continue
				}
				// The object has already been deleted let if fall of
				// the edge of the world. Hitting this could mean our
				// GC logic deleted a process too early.
				// TBD add a counter around this to alert on it.
				if p.color == deleted {
					continue
				}
				p.color = deletePending
				deleteQueue = append(deleteQueue, p)
			}
		}
	}()
}

func (pc *processCache) deletePending(process *processInternal) {
	pc.deleteChan <- process
}

func (pc *processCache) refDec(p *processInternal) {
	ref := atomic.AddUint32(&p.process.Refcnt, ^uint32(0))
	if ref == 0 {
		pc.deletePending(p)
	}
}

func (pc *processCache) refInc(p *processInternal) {
	atomic.AddUint32(&p.process.Refcnt, 1)
}

func newProcessCache(
	log logrus.FieldLogger,
	processCacheSize int,
) (*processCache, error) {
	lruCache, err := lru.New(processCacheSize)
	if err != nil {
		return nil, err
	}
	pidMap, err := lru.New(processCacheSize)
	if err != nil {
		return nil, err
	}
	pm := &processCache{
		log:    log,
		cache:  lruCache,
		pidMap: pidMap,
	}
	update := func() {
		metrics.ExecveMapSize.WithLabelValues("processLru", strconv.Itoa(processCacheSize)).Set(float64(pm.cache.Len()))
		metrics.ExecveMapSize.WithLabelValues("pidMap", strconv.Itoa(processCacheSize)).Set(float64(pm.pidMap.Len()))
	}
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				update()
			}
		}
	}()
	pm.cacheGarbageCollector()
	return pm, nil
}

func (pc *processCache) get(processID string) (*processInternal, error) {
	entry, ok := pc.cache.Get(processID)
	if !ok {
		pc.log.WithField("id in event", processID).Debug("process not found in cache")
		metrics.ErrorCount.WithLabelValues(string(metrics.ProcessCacheMissOnGet)).Inc()
		return nil, fmt.Errorf("invalid entry for process ID: %s", processID)
	}
	process, _ := entry.(*processInternal)
	if !ok {
		pc.log.WithField("process entry", entry).Debug("invalid entry in process cache")
		metrics.ErrorCount.WithLabelValues(string(metrics.ProcessCacheMissOnGet)).Inc()
		return nil, fmt.Errorf("process with ID %s not found in cache", processID)
	}
	return process, nil
}

func (pc *processCache) add(process *processInternal) bool {
	evicted := pc.cache.Add(process.process.ExecId, process)
	if evicted {
		metrics.ErrorCount.WithLabelValues(string(metrics.ProcessCacheEvicted)).Inc()
	}
	return evicted
}

func (pc *processCache) remove(process *fgs.Process) bool {
	present := pc.cache.Remove(process.ExecId)
	if !present {
		metrics.ErrorCount.WithLabelValues(string(metrics.ProcessCacheMissOnRemove)).Inc()
	}
	if process.Pid != nil {
		pidFound := pc.pidMap.Remove(process.Pid.Value)
		if !pidFound {
			metrics.ErrorCount.WithLabelValues(string(metrics.PidMapMissOnRemove)).Inc()
		}
	}
	return present
}

func (pc *processCache) len() int {
	return pc.cache.Len()
}

// Get the exec ID for a given PID. If PID is not found, it returns an empty string.
func (pc *processCache) getFromPidMap(pid uint32) string {
	entry, ok := pc.pidMap.Get(pid)
	if !ok {
		return ""
	}
	execID, ok := entry.(string)
	if !ok {
		pc.log.WithFields(logrus.Fields{"pid": pid, "execID": execID}).Warn("Invalid entry in pidMap")
		metrics.ErrorCount.WithLabelValues(string(metrics.PidMapInvalidEntry)).Inc()
		return ""
	}
	return execID
}

func (pc *processCache) addToPidMap(pid uint32, execID string) bool {
	evicted := pc.pidMap.Add(pid, execID)
	if evicted {
		pc.log.Warn("Entry evicted from pidMap")
		metrics.ErrorCount.WithLabelValues(string(metrics.PidMapEvicted)).Inc()
	}
	return evicted
}
