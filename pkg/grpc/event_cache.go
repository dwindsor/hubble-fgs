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
	"net"
	"time"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/metrics"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/sirupsen/logrus"
)

type eventNetObj interface {
	GetProcess() *fgs.Process
}

type eventNetCacheObj struct {
	event     eventNetObj
	timestamp *timestamp.Timestamp
	color     int
	msg       interface{}
}

type eventProcCacheObj struct {
	process   *fgs.ProcessExec
	timestamp *timestamp.Timestamp
	color     int
	msg       *api.MsgExecveEventUnix
}

type eventCache struct {
	log       logrus.FieldLogger
	netCache  []eventNetCacheObj
	procCache []eventProcCacheObj
	pm        *ProcessManager
}

// garbage collection states
const (
	newEntry     = iota
	oneStrikes   = 1
	twoStrikes   = 2
	threeStrikes = 3
)

// garbage collection run interval
const (
	eventRetryTimer = time.Second * 10
)

func (ec *eventCache) eventLabels(endpoint *v1.Endpoint, destinationIp string) []string {
	var labels []string

	if endpoint == nil {
		return labels
	}
	ip := net.ParseIP(destinationIp)
	if ip == nil {
		labels = ec.pm.ciliumState.GetFQDNCache().GetNamesOf(endpoint.ID, ip)
	}

	return labels
}

func (ec *eventCache) handleNetEvents() {
	tmp := ec.netCache[:0]
	for _, e := range ec.netCache {
		var processedEvent *fgs.GetEventsResponse

		/* Ensure we actually have a dockerID, we use this for testing reasons
		 * mostly. It is nice though if we ever hit this case to just post it.
		 */
		endpoint := ec.pm.getProcessEndpoint(e.event.GetProcess())
		if e.event.GetProcess().GetDocker() != "" {
			/* If the Pod is nil because process event is incomplete lets
			 * wait and hopefully it is eventually updated from handleProcEvents.
			 */
			if endpoint == nil || e.event.GetProcess().Pod == nil {
				e.color++
				if e.color != threeStrikes {
					tmp = append(tmp, e)
					continue
				}
				metrics.EventCacheCount.WithLabelValues(string(metrics.EventCacheEndpointRetryFailed)).Inc()
			}
		}

		switch event := e.event.(type) {
		case *fgs.ProcessClose:
			event.DestinationNames = ec.eventLabels(endpoint, event.GetDestinationIp())
			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessClose{ProcessClose: event},
				NodeName: ec.pm.nodeName,
				Time:     e.timestamp,
			}
		case *fgs.ProcessConnect:
			event.DestinationNames = ec.eventLabels(endpoint, event.GetDestinationIp())
			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessConnect{ProcessConnect: event},
				NodeName: ec.pm.nodeName,
				Time:     e.timestamp,
			}
		case *fgs.ProcessAccept:
			event.DestinationNames = ec.eventLabels(endpoint, event.GetDestinationIp())
			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessAccept{ProcessAccept: event},
				NodeName: ec.pm.nodeName,
				Time:     e.timestamp,
			}
		case *fgs.ProcessListen:
			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessListen{ProcessListen: event},
				NodeName: ec.pm.nodeName,
				Time:     e.timestamp,
			}
		case *fgs.ProcessCred:
			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessCred{ProcessCred: event},
				NodeName: ec.pm.nodeName,
				Time:     e.timestamp,
			}
		case *fgs.ProcessExit:
			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessExit{ProcessExit: event},
				NodeName: ec.pm.nodeName,
				Time:     e.timestamp,
			}
		case *fgs.Tls:
			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_Tls{Tls: event},
				NodeName: ec.pm.nodeName,
				Time:     e.timestamp,
			}
		case *fgs.ProcessKprobe:
			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessKprobe{ProcessKprobe: event},
				NodeName: ec.pm.nodeName,
				Time:     e.timestamp,
			}
		}

		ec.pm.notifyListeners(e.msg, processedEvent)
	}
	ec.netCache = tmp
}

func (ec *eventCache) handleProcEvents() {
	tmp := ec.procCache[:0]
	for _, e := range ec.procCache {
		containerId := e.process.Process.Docker
		filename := e.process.Process.Binary
		args := e.process.Process.Arguments
		nspid := e.msg.Process.NSPID

		podInfo, _ := ec.pm.getPodInfo(containerId, filename, args, nspid)
		if podInfo == nil {
			e.color++
			if e.color != threeStrikes {
				tmp = append(tmp, e)
				continue
			}
			metrics.EventCacheCount.WithLabelValues(string(metrics.EventCachePodInfoRetryFailed)).Inc()
		}
		/* In addition to holding this event until podInfo is available we
		 * also need to ensure that any future references in the process
		 * cache will also get the updated podInfo. So reach into the cache
		 * and set the podInfo.
		 */
		processInternal, err := ec.pm.cache.get(e.process.Process.ExecId)
		if err != nil {
			ec.log.WithField("Process", e.process.Process).Warn("eventCache to procCache lookup failed ")
		} else {
			processInternal.process.Pod = podInfo
		}
		e.process.Process.Pod = podInfo
		processedEvent := &fgs.GetEventsResponse{
			Event:    &fgs.GetEventsResponse_ProcessExec{ProcessExec: e.process},
			NodeName: ec.pm.nodeName,
			Time:     e.timestamp,
		}
		ec.pm.notifyListeners(e.msg, processedEvent)
	}
	ec.procCache = tmp
}

func (ec *eventCache) eventRetry() {
	ticker := time.NewTicker(eventRetryTimer)

	/* Every 'eventRetryTimer' walk the slice of events pending pod info. If
	 * an event hasn't completed its podInfo after two iterations send the
	 * event anyways.
	 */
	go func() {
		for {
			select {
			case <-ticker.C:
				ec.handleNetEvents()
				ec.handleProcEvents()
				metrics.ExecveMapSize.WithLabelValues("netCache", "0").Set(float64(len(ec.netCache)))
				metrics.ExecveMapSize.WithLabelValues("procCache", "0").Set(float64(len(ec.procCache)))
			}
		}
	}()
}

func newEventCache(log logrus.FieldLogger, pm *ProcessManager) *eventCache {
	ec := &eventCache{
		log:       log,
		netCache:  make([]eventNetCacheObj, 0),
		procCache: make([]eventProcCacheObj, 0),
		pm:        pm,
	}
	ec.eventRetry()
	return ec
}

func (ec *eventCache) add(e eventNetObj, t *timestamp.Timestamp, msg interface{}) {
	event := eventNetCacheObj{event: e, timestamp: t, msg: msg}
	metrics.EventCacheCount.WithLabelValues(string(metrics.EventCacheNetworkCount)).Inc()
	ec.netCache = append(ec.netCache, event)
}

func (ec *eventCache) addProc(e *fgs.ProcessExec, t *timestamp.Timestamp, msg *api.MsgExecveEventUnix) {
	event := eventProcCacheObj{process: e, timestamp: t, msg: msg}
	metrics.EventCacheCount.WithLabelValues(string(metrics.EventCacheProcessCount)).Inc()
	ec.procCache = append(ec.procCache, event)
}
