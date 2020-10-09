package grpc

import (
	"fmt"
	"strconv"
	"time"

	"github.com/covalentio/hubble-fgs/api/v1/fgs"
	"github.com/covalentio/hubble-fgs/pkg/metrics"
	lru "github.com/hashicorp/golang-lru"
	"github.com/sirupsen/logrus"
)

type processCache struct {
	log   logrus.FieldLogger
	cache *lru.Cache
}

// processInternal is the internal representation of a process.
type processInternal struct {
	// externally visible process struct.
	process *fgs.Process
	// additional internal fields below
	capabilities *fgs.Capabilities
}

func newProcessCache(
	log logrus.FieldLogger,
	processCacheSize int,
) (*processCache, error) {
	lruCache, err := lru.New(processCacheSize)
	if err != nil {
		return nil, err
	}
	pm := &processCache{
		log:   log,
		cache: lruCache,
	}
	update := func() {
		metrics.ExecveMapSize.WithLabelValues("processLru", strconv.Itoa(processCacheSize)).Set(float64(pm.cache.Len()))
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

func (pc *processCache) remove(processID string) bool {
	present := pc.cache.Remove(processID)
	if !present {
		metrics.ErrorCount.WithLabelValues(string(metrics.ProcessCacheMissOnRemove)).Inc()
	}
	return present
}

func (pc *processCache) len() int {
	return pc.cache.Len()
}
