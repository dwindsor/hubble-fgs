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
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/metrics"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var hostNamespace *fgs.Namespaces

type listener interface {
	notify(res *fgs.GetEventsResponse)
}

type notifier interface {
	addListener(listener listener)
	removeListener(listener listener)
}

// ProcessManager maintains a cache of processes from fgs exec events.
type ProcessManager struct {
	log        logrus.FieldLogger
	cache      *processCache
	eventCache *eventCache
	nodeName   string
	watcher    K8sResourceWatcher
	// synchronize access to the listeners map.
	mux                    sync.Mutex
	listeners              map[listener]struct{}
	ciliumState            *cilium.State
	enableProcessCred      bool
	enableProcessNs        bool
	enableEventCache       bool
	enableCilium           bool
	enableProcessAncestors bool
	dns                    *dnsCache
}

// NewProcessManager returns a pointer to an initialized ProcessManager struct.
func NewProcessManager(
	log logrus.FieldLogger,
	processCacheSize int,
	watcher K8sResourceWatcher,
	ciliumState *cilium.State,
	enableProcessCred bool,
	enableProcessNs bool,
	enableEventCache bool,
	enableCilium bool,
	enableProcessAncestors bool,
) (*ProcessManager, error) {
	cache, err := newProcessCache(log, processCacheSize)
	if err != nil {
		return nil, err
	}

	dnsCache, err := newDnsCache()
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS cache %w", err)
	}

	pm := &ProcessManager{
		log:                    log,
		cache:                  cache,
		nodeName:               reader.GetNodeNameForExport(),
		watcher:                watcher,
		ciliumState:            ciliumState,
		listeners:              make(map[listener]struct{}),
		enableProcessCred:      enableProcessCred,
		enableProcessNs:        enableProcessNs,
		enableEventCache:       enableEventCache,
		enableCilium:           enableCilium,
		enableProcessAncestors: enableProcessAncestors,
		dns:                    dnsCache,
	}

	if enableEventCache {
		pm.eventCache = newEventCache(log, pm)
	}

	pm.log.WithField("enableCilium", enableCilium).WithFields(logrus.Fields{
		"enableEventCache":  enableEventCache,
		"enableProcessCred": enableProcessCred,
		"enableProcessNs":   enableProcessNs,
		"processCacheSize":  processCacheSize,
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
		pm.notifyListeners(event, processedEvent)
	}
	return nil
}

// Close implements Listener.Close.
func (pm *ProcessManager) Close() error {
	return nil
}

func ktimeToProto(ktime uint64) *timestamppb.Timestamp {
	return ktimeToProtoOpt(ktime, true)
}

func ktimeToProtoOpt(ktime uint64, monotonic bool) *timestamppb.Timestamp {
	decodedTime, err := reader.DecodeKtime(int64(ktime), monotonic)
	if err != nil {
		logrus.WithError(err).WithField("ktime", ktime).Warn("Failed to decode ktime")
		return timestamppb.Now()
	}
	return timestamppb.New(decodedTime)
}

func (pm *ProcessManager) addListener(listener listener) {
	logger.GetLogger().WithField("getEventsListener", listener).Debug("Adding a getEventsListener")
	pm.mux.Lock()
	defer pm.mux.Unlock()
	pm.listeners[listener] = struct{}{}
}

func (pm *ProcessManager) removeListener(listener listener) {
	logger.GetLogger().WithField("getEventsListener", listener).Debug("Removing a getEventsListener")
	pm.mux.Lock()
	defer pm.mux.Unlock()
	delete(pm.listeners, listener)
}

func (pm *ProcessManager) notifyListeners(original interface{}, processed *fgs.GetEventsResponse) {
	pm.mux.Lock()
	defer pm.mux.Unlock()
	for l := range pm.listeners {
		l.notify(processed)
	}
	metrics.ProcessEvent(original, processed)
}
