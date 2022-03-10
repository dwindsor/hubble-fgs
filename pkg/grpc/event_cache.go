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
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type eventNetObj interface {
	GetProcess() *fgs.Process
}

type eventNetCacheObj struct {
	event     eventNetObj
	timestamp *timestamppb.Timestamp
	color     int
	msg       interface{}
}

type eventProcCacheObj struct {
	process   *fgs.ProcessExec
	timestamp *timestamppb.Timestamp
	color     int
	msg       *api.MsgExecveEventUnix
}

type eventCache struct {
	netObjsChan  chan eventNetCacheObj
	procObjsChan chan eventProcCacheObj
	log          logrus.FieldLogger
	netCache     []eventNetCacheObj
	procCache    []eventProcCacheObj
	pm           *ProcessManager
}

// garbage collection states
const (
	threeStrikes = 3
)

// garbage collection run interval
const (
	eventRetryTimer = time.Second * 10
)

func (ec *eventCache) eventLabels(endpoint *v1.Endpoint, event *eventNetCacheObj) ([]string, error) {
	destinationIp := ""
	var labels []string

	switch e := event.event.(type) {
	case *fgs.ProcessConnect:
		destinationIp = e.GetDestinationIp()
		if len(e.DestinationNames) > 0 {
			return e.DestinationNames, nil
		}
	case *fgs.ProcessClose:
		destinationIp = e.GetDestinationIp()
		if len(e.DestinationNames) > 0 {
			return e.DestinationNames, nil
		}
	case *fgs.ProcessAccept:
		destinationIp = e.GetDestinationIp()
		if len(e.DestinationNames) > 0 {
			return e.DestinationNames, nil
		}
	default:
		return labels, nil
	}
	return ec.pm.dns.GetIp(destinationIp)
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
				if e.color < threeStrikes {
					tmp = append(tmp, e)
					continue
				}
				metrics.EventCacheCount.WithLabelValues(string(metrics.EventCacheEndpointRetryFailed)).Inc()
			}
		}

		labels, err := ec.eventLabels(endpoint, &e)
		if err != nil {
			e.color++
			if e.color < threeStrikes {
				tmp = append(tmp, e)
				continue
			}
			metrics.EventCacheCount.WithLabelValues(string(metrics.EventCacheEndpointRetryFailed)).Inc()
		}

		switch event := e.event.(type) {
		case *fgs.ProcessClose:
			event.DestinationNames = labels
			if event.DestinationPod == nil {
				event.DestinationPod = ec.pm.getPodInfoOfIp(net.ParseIP(event.DestinationIp))
			}

			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessClose{ProcessClose: event},
				NodeName: ec.pm.nodeName,
				Time:     e.timestamp,
			}
		case *fgs.ProcessConnect:
			event.DestinationNames = labels
			if event.DestinationPod == nil {
				event.DestinationPod = ec.pm.getPodInfoOfIp(net.ParseIP(event.DestinationIp))
			}

			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessConnect{ProcessConnect: event},
				NodeName: ec.pm.nodeName,
				Time:     e.timestamp,
			}
		case *fgs.ProcessAccept:
			event.DestinationNames = labels
			if event.DestinationPod == nil {
				event.DestinationPod = ec.pm.getPodInfoOfIp(net.ParseIP(event.DestinationIp))
			}

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
		case *fgs.ProcessHttp:
			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessHttp{ProcessHttp: event},
				NodeName: ec.pm.nodeName,
				Time:     e.timestamp,
			}
		case *fgs.ProcessSockStats:
			if event.Socket.DestinationPod == nil {
				event.Socket.DestinationPod = ec.pm.getPodInfoOfIp(net.ParseIP(event.Socket.DestinationIp))
			}
			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessSockstats{ProcessSockstats: event},
				NodeName: ec.pm.nodeName,
				Time:     e.timestamp,
			}
		case *fgs.ProcessKprobe:
			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessKprobe{ProcessKprobe: event},
				NodeName: ec.pm.nodeName,
				Time:     e.timestamp,
			}
		case *fgs.ProcessDns:
			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessDns{ProcessDns: event},
				NodeName: ec.pm.nodeName,
				Time:     e.timestamp,
			}
		case *fgs.ProcessNetworkBurst:
			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessNetworkBurst{ProcessNetworkBurst: event},
				NodeName: ec.pm.nodeName,
				Time:     e.timestamp,
			}
		}

		if processedEvent == nil {
			ec.log.WithField("event", e.event).Warn("eventType unhandled")
		} else {
			ec.pm.notifyListeners(e.msg, processedEvent)
		}
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
			processInternal.mu.Lock()
			processInternal.process.Pod = podInfo
			processInternal.mu.Unlock()
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

func (ec *eventCache) loop() {
	ticker := time.NewTicker(eventRetryTimer)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			/* Every 'eventRetryTimer' walk the slice of events pending pod info. If
			 * an event hasn't completed its podInfo after two iterations send the
			 * event anyways.
			 */
			ec.handleNetEvents()
			ec.handleProcEvents()
			metrics.ExecveMapSize.WithLabelValues("netCache", "0").Set(float64(len(ec.netCache)))
			metrics.ExecveMapSize.WithLabelValues("procCache", "0").Set(float64(len(ec.procCache)))

		case event := <-ec.netObjsChan:
			metrics.EventCacheCount.WithLabelValues(string(metrics.EventCacheNetworkCount)).Inc()
			ec.netCache = append(ec.netCache, event)

		case event := <-ec.procObjsChan:
			metrics.EventCacheCount.WithLabelValues(string(metrics.EventCacheProcessCount)).Inc()
			ec.procCache = append(ec.procCache, event)
		}
	}
}

func newEventCache(log logrus.FieldLogger, pm *ProcessManager) *eventCache {
	ec := &eventCache{
		netObjsChan:  make(chan eventNetCacheObj),
		procObjsChan: make(chan eventProcCacheObj),
		log:          log,
		netCache:     make([]eventNetCacheObj, 0),
		procCache:    make([]eventProcCacheObj, 0),
		pm:           pm,
	}
	go ec.loop()
	return ec
}

func (ec *eventCache) add(e eventNetObj, t *timestamppb.Timestamp, msg interface{}) {
	ec.netObjsChan <- eventNetCacheObj{event: e, timestamp: t, msg: msg}
}

func (ec *eventCache) addProc(e *fgs.ProcessExec, t *timestamppb.Timestamp, msg *api.MsgExecveEventUnix) {
	ec.procObjsChan <- eventProcCacheObj{process: e, timestamp: t, msg: msg}
}
