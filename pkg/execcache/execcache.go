//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package execcache

import (
	"time"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api/processapi"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/metrics"
	"github.com/isovalent/hubble-fgs/pkg/process"
	"github.com/isovalent/hubble-fgs/pkg/reader/node"
	"github.com/isovalent/hubble-fgs/pkg/server"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// garbage collection states
const (
	threeStrikes = 3
)

// garbage collection run interval
const (
	eventRetryTimer = time.Second * 10
)

var (
	nodeName string
)

type cacheObj struct {
	internal  *process.ProcessInternal
	process   *fgs.ProcessExec
	timestamp *timestamppb.Timestamp
	color     int
	msg       *processapi.MsgExecveEventUnix
}

type Cache struct {
	objsChan chan cacheObj
	cache    []cacheObj
	dns      *dns.Cache
	server   *server.Server
}

func (ec *Cache) handleExecEvents() {
	tmp := ec.cache[:0]
	for _, e := range ec.cache {
		containerId := e.process.Process.Docker
		filename := e.process.Process.Binary
		args := e.process.Process.Arguments
		nspid := e.msg.Process.NSPID

		podInfo, _ := process.GetPodInfo(containerId, filename, args, nspid)
		if podInfo == nil {
			e.color++
			if e.color != threeStrikes {
				tmp = append(tmp, e)
				continue
			}
			metrics.EventCacheCount.WithLabelValues(string(metrics.EventCachePodInfoRetryFailed)).Inc()
		}

		if e.internal != nil {
			e.internal.AddPodInfo(podInfo)
			e.process.Process = e.internal.GetProcessCopy()
		} else {
			e.process.Process.Pod = podInfo
		}

		processedEvent := &fgs.GetEventsResponse{
			Event:    &fgs.GetEventsResponse_ProcessExec{ProcessExec: e.process},
			NodeName: nodeName,
			Time:     e.timestamp,
		}
		ec.server.NotifyListeners(e.msg, processedEvent)
	}
	ec.cache = tmp
}

func (ec *Cache) loop() {
	ticker := time.NewTicker(eventRetryTimer)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			/* Every 'eventRetryTimer' walk the slice of events pending pod info. If
			 * an event hasn't completed its podInfo after two iterations send the
			 * event anyways.
			 */
			ec.handleExecEvents()
			metrics.ExecveMapSize.WithLabelValues("cache", "0").Set(float64(len(ec.cache)))

		case event := <-ec.objsChan:
			metrics.EventCacheCount.WithLabelValues(string(metrics.EventCacheProcessCount)).Inc()
			ec.cache = append(ec.cache, event)
		}
	}
}

func (ec *Cache) Add(internal *process.ProcessInternal,
	e *fgs.ProcessExec,
	t *timestamppb.Timestamp,
	msg *processapi.MsgExecveEventUnix) {
	ec.objsChan <- cacheObj{internal: internal, process: e, timestamp: t, msg: msg}
}

func New(s *server.Server, dns *dns.Cache) *Cache {
	ec := &Cache{
		objsChan: make(chan cacheObj),
		cache:    make([]cacheObj, 0),
		dns:      dns,
		server:   s,
	}
	nodeName = node.GetNodeNameForExport()
	go ec.loop()
	return ec
}
