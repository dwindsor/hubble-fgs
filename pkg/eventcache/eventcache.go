//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package eventcache

import (
	"net"
	"time"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/metrics"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
	"github.com/isovalent/hubble-fgs/pkg/process"
	"github.com/isovalent/hubble-fgs/pkg/reader"
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

type eventObj interface {
	GetProcess() *fgs.Process
}

var (
	nodeName string
)

type cacheObj struct {
	internal  *process.ProcessInternal
	event     eventObj
	timestamp *timestamppb.Timestamp
	color     int
	msg       interface{}
}

type Cache struct {
	objsChan chan cacheObj
	cache    []cacheObj
	dns      *dns.Cache
	server   *server.Server
}

func (ec *Cache) eventLabels(endpoint *v1.Endpoint, event *cacheObj) ([]string, error) {
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
	return ec.dns.GetIp(destinationIp)
}

func (ec *Cache) handleNetEvents() {
	tmp := ec.cache[:0]
	for _, e := range ec.cache {
		var processedEvent *fgs.GetEventsResponse

		/* Ensure we actually have a dockerID, we use this for testing reasons
		 * mostly. It is nice though if we ever hit this case to just post it.
		 */
		endpoint := process.GetProcessEndpoint(e.event.GetProcess())
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
			if e.internal != nil {
				// Make a copy of the process in order to not hand a mutating object to protobuf/grpc.
				event.Process = e.internal.GetProcessCopy()
			}
			event.DestinationNames = labels
			if event.DestinationPod == nil {
				event.DestinationPod = podinfo.GetPodInfoOfIp(net.ParseIP(event.DestinationIp))
			}

			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessClose{ProcessClose: event},
				NodeName: nodeName,
				Time:     e.timestamp,
			}
		case *fgs.ProcessConnect:
			if e.internal != nil {
				event.Process = e.internal.GetProcessCopy()
			}
			event.DestinationNames = labels
			if event.DestinationPod == nil {
				event.DestinationPod = podinfo.GetPodInfoOfIp(net.ParseIP(event.DestinationIp))
			}

			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessConnect{ProcessConnect: event},
				NodeName: nodeName,
				Time:     e.timestamp,
			}
		case *fgs.ProcessAccept:
			if e.internal != nil {
				event.Process = e.internal.GetProcessCopy()
			}
			event.DestinationNames = labels
			if event.DestinationPod == nil {
				event.DestinationPod = podinfo.GetPodInfoOfIp(net.ParseIP(event.DestinationIp))
			}

			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessAccept{ProcessAccept: event},
				NodeName: nodeName,
				Time:     e.timestamp,
			}
		case *fgs.ProcessListen:
			if e.internal != nil {
				event.Process = e.internal.GetProcessCopy()
			}
			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessListen{ProcessListen: event},
				NodeName: nodeName,
				Time:     e.timestamp,
			}
		case *fgs.ProcessCred:
			if e.internal != nil {
				event.Process = e.internal.GetProcessCopy()
			}
			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessCred{ProcessCred: event},
				NodeName: nodeName,
				Time:     e.timestamp,
			}
		case *fgs.ProcessExit:
			if e.internal != nil {
				event.Process = e.internal.GetProcessCopy()
			}
			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessExit{ProcessExit: event},
				NodeName: nodeName,
				Time:     e.timestamp,
			}
		case *fgs.Tls:
			if e.internal != nil {
				event.Process = e.internal.GetProcessCopy()
			}
			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_Tls{Tls: event},
				NodeName: nodeName,
				Time:     e.timestamp,
			}
		case *fgs.ProcessHttp:
			if e.internal != nil {
				event.Process = e.internal.GetProcessCopy()
			}
			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessHttp{ProcessHttp: event},
				NodeName: nodeName,
				Time:     e.timestamp,
			}
		case *fgs.ProcessSockStats:
			if e.internal != nil {
				event.Process = e.internal.GetProcessCopy()
			}
			if event.Socket.DestinationPod == nil {
				event.Socket.DestinationPod = podinfo.GetPodInfoOfIp(net.ParseIP(event.Socket.DestinationIp))
			}
			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessSockStats{ProcessSockStats: event},
				NodeName: nodeName,
				Time:     e.timestamp,
			}
		case *fgs.ProcessKprobe:
			if e.internal != nil {
				event.Process = e.internal.GetProcessCopy()
			}
			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessKprobe{ProcessKprobe: event},
				NodeName: nodeName,
				Time:     e.timestamp,
			}
		case *fgs.ProcessDns:
			if e.internal != nil {
				event.Process = e.internal.GetProcessCopy()
			}
			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessDns{ProcessDns: event},
				NodeName: nodeName,
				Time:     e.timestamp,
			}
		case *fgs.ProcessNetworkBurst:
			if e.internal != nil {
				event.Process = e.internal.GetProcessCopy()
			}
			processedEvent = &fgs.GetEventsResponse{
				Event:    &fgs.GetEventsResponse_ProcessNetworkBurst{ProcessNetworkBurst: event},
				NodeName: nodeName,
				Time:     e.timestamp,
			}
		}

		if processedEvent == nil {
			logger.GetLogger().WithField("event", e.event).Warn("eventType unhandled")
		} else {
			ec.server.NotifyListeners(e.msg, processedEvent)
		}
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
			ec.handleNetEvents()
			metrics.ExecveMapSize.WithLabelValues("netCache", "0").Set(float64(len(ec.cache)))

		case event := <-ec.objsChan:
			metrics.EventCacheCount.WithLabelValues(string(metrics.EventCacheNetworkCount)).Inc()
			ec.cache = append(ec.cache, event)
		}
	}
}

// We handle two race conditions here one where the event races with
// an FGS execve event and the other -- much more common -- where we
// race with K8s watcher
// case 1 (execve race):
//  Its possible to receive this FGS event before the process event cache
//  has been populated with a FGS execve event. In this case we need to
//  cache the event until the process cache is populated.
// case 2 (k8s watcher race):
//  Its possible to receive an event before the k8s watcher receives the
//  podInfo event and populates the local cache. If we expect podInfo,
//  indicated by having a nonZero dockerID we cache the event until the
//  podInfo arrives.
func (ec *Cache) Needed(proc *fgs.Process) bool {
	if proc == nil {
		return true
	}
	if proc.Docker != "" && proc.Pod == nil {
		return true
	}
	return false
}

func (ec *Cache) Add(internal *process.ProcessInternal,
	e eventObj,
	t *timestamppb.Timestamp,
	msg interface{}) {
	ec.objsChan <- cacheObj{internal: internal, event: e, timestamp: t, msg: msg}
}

func New(s *server.Server, dns *dns.Cache) *Cache {
	ec := &Cache{
		objsChan: make(chan cacheObj),
		cache:    make([]cacheObj, 0),
		dns:      dns,
		server:   s,
	}
	nodeName = reader.GetNodeNameForExport()
	go ec.loop()
	return ec
}
