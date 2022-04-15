//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package grpc

import (
	"fmt"
	"sync"

	"github.com/cilium/hubble/pkg/cilium"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/eventcache"
	"github.com/isovalent/hubble-fgs/pkg/execcache"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/metrics"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/server"
	"github.com/sirupsen/logrus"
)

// ProcessManager maintains a cache of processes from fgs exec events.
type ProcessManager struct {
	log        logrus.FieldLogger
	eventCache *eventcache.Cache
	execCache  *execcache.Cache
	nodeName   string
	Server     *server.Server
	// synchronize access to the listeners map.
	mux                    sync.Mutex
	listeners              map[server.Listener]struct{}
	ciliumState            *cilium.State
	enableProcessCred      bool
	enableProcessNs        bool
	enableEventCache       bool
	enableCilium           bool
	enableProcessAncestors bool
	dns                    *dns.Cache
}

// NewProcessManager returns a pointer to an initialized ProcessManager struct.
func NewProcessManager(
	log logrus.FieldLogger,
	ciliumState *cilium.State,
	manager *sensors.Manager,
	enableProcessCred bool,
	enableProcessNs bool,
	enableEventCache bool,
	enableCilium bool,
	enableProcessAncestors bool,
) (*ProcessManager, error) {
	dnsCache, err := dns.NewCache()
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS cache %w", err)
	}

	pm := &ProcessManager{
		log:                    log,
		nodeName:               reader.GetNodeNameForExport(),
		ciliumState:            ciliumState,
		listeners:              make(map[server.Listener]struct{}),
		enableProcessCred:      enableProcessCred,
		enableProcessNs:        enableProcessNs,
		enableEventCache:       enableEventCache,
		enableCilium:           enableCilium,
		enableProcessAncestors: enableProcessAncestors,
		dns:                    dnsCache,
	}

	pm.Server = server.NewServer(pm, manager)
	pm.eventCache = eventcache.New(pm.Server, pm.dns)
	pm.execCache = execcache.New(pm.Server, pm.dns)

	pm.log.WithField("enableCilium", enableCilium).WithFields(logrus.Fields{
		"enableEventCache":  enableEventCache,
		"enableProcessCred": enableProcessCred,
		"enableProcessNs":   enableProcessNs,
	}).Info("Starting process manager")
	return pm, nil
}

// Notify implements Listener.Notify.
func (pm *ProcessManager) Notify(event interface{}) error {
	var processedEvent *fgs.GetEventsResponse
	switch msg := event.(type) {
	case *api.MsgFGSReady:
		// pass
	case *api.MsgTLSEventUnix:
		processedEvent = pm.handleTLSMessage(msg)
	case *api.MsgHttpEventUnix:
		processedEvent = pm.handleHttpMessage(msg)
	case *api.MsgExecveEventUnix:
		processedEvent = pm.handleExecveMessage(msg)
	case *api.MsgIPv4EventUnix:
		processedEvent = pm.HandleIpMessage(msg)
	case *api.MsgProcessNetworkBurstEventUnix:
		processedEvent = pm.handleProcessNetworkBurstMessage(msg)
	case *api.MsgInterfaceEventUnix:
		processedEvent = pm.handleInterfaceMessage(msg)
	case *api.MsgIPv4DnsUnix:
		processedEvent = pm.handleDnsMessage(msg)
	case *api.MsgExitEventUnix:
		processedEvent = pm.handleExitMessage(msg)
	case *api.MsgCredEventUnix:
		processedEvent = pm.handleCredMessage(msg)
	case *api.MsgKfreeSkbUnix:
		processedEvent = pm.handleKfreeSkbMessage(msg)
	case *api.MsgGenericKprobeUnix:
		processedEvent = pm.handleGenericKprobeMessage(msg)
	case *api.MsgGenericTracepointUnix:
		processedEvent = pm.handleGenericTracepointMessage(msg)
	case *api.MsgTestEventUnix:
		processedEvent = pm.handleTestMessage(msg)

	default:
		pm.log.WithField("event", event).Warnf("unhandled event of type %T", msg)
		metrics.ErrorCount.WithLabelValues(string(metrics.UnhandledEvent)).Inc()
		return nil
	}
	if processedEvent != nil {
		pm.NotifyListener(event, processedEvent)
	}
	return nil
}

// Close implements Listener.Close.
func (pm *ProcessManager) Close() error {
	return nil
}

func (pm *ProcessManager) AddListener(listener server.Listener) {
	logger.GetLogger().WithField("getEventsListener", listener).Debug("Adding a getEventsListener")
	pm.mux.Lock()
	defer pm.mux.Unlock()
	pm.listeners[listener] = struct{}{}
}

func (pm *ProcessManager) RemoveListener(listener server.Listener) {
	logger.GetLogger().WithField("getEventsListener", listener).Debug("Removing a getEventsListener")
	pm.mux.Lock()
	defer pm.mux.Unlock()
	delete(pm.listeners, listener)
}

func (pm *ProcessManager) NotifyListener(original interface{}, processed *fgs.GetEventsResponse) {
	pm.mux.Lock()
	defer pm.mux.Unlock()
	for l := range pm.listeners {
		l.Notify(processed)
	}
	metrics.ProcessEvent(original, processed)
}
