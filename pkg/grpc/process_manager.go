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
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/api/readyapi"
	"github.com/cilium/tetragon/pkg/api/testapi"
	"github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api/dnsapi"
	"github.com/isovalent/hubble-fgs/pkg/api/httpapi"
	"github.com/isovalent/hubble-fgs/pkg/api/kfreeapi"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/tlsapi"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/eventcache"
	"github.com/isovalent/hubble-fgs/pkg/execcache"
	"github.com/isovalent/hubble-fgs/pkg/grpc/burst"
	"github.com/isovalent/hubble-fgs/pkg/grpc/dnsproto"
	"github.com/isovalent/hubble-fgs/pkg/grpc/exec"
	"github.com/isovalent/hubble-fgs/pkg/grpc/execAncestors"
	"github.com/isovalent/hubble-fgs/pkg/grpc/httpproto"
	"github.com/isovalent/hubble-fgs/pkg/grpc/iface"
	"github.com/isovalent/hubble-fgs/pkg/grpc/kfree"
	"github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	"github.com/isovalent/hubble-fgs/pkg/grpc/test"
	"github.com/isovalent/hubble-fgs/pkg/grpc/tls"
	"github.com/isovalent/hubble-fgs/pkg/grpc/tracing"
	"github.com/isovalent/hubble-fgs/pkg/metrics"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/server"
	"github.com/sirupsen/logrus"
)

type execProcess interface {
	HandleExecveMessage(*processapi.MsgExecveEventUnix) *fgs.GetEventsResponse
	HandleExitMessage(*processapi.MsgExitEventUnix) *fgs.GetEventsResponse
	HandleCloneMessage(*processapi.MsgCloneEventUnix)
}

var (
	tlsGrpc     *tls.Grpc
	layer3Grpc  *layer3.Grpc
	dnsGrpc     *dnsproto.Grpc
	httpGrpc    *httpproto.Grpc
	tracingGrpc *tracing.Grpc
	execGrpc    execProcess
)

// ProcessManager maintains a cache of processes from fgs exec events.
type ProcessManager struct {
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
	ciliumState *cilium.State,
	manager *sensors.Manager,
	enableProcessCred bool,
	enableProcessNs bool,
	enableEventCache bool,
	enableCilium bool,
	enableProcessAncestors bool,
) (*ProcessManager, error) {
	var err error

	pm := &ProcessManager{
		nodeName:               node.GetNodeNameForExport(),
		ciliumState:            ciliumState,
		listeners:              make(map[server.Listener]struct{}),
		enableProcessCred:      enableProcessCred,
		enableProcessNs:        enableProcessNs,
		enableEventCache:       enableEventCache,
		enableCilium:           enableCilium,
		enableProcessAncestors: enableProcessAncestors,
	}

	pm.dns, err = dns.NewCache()
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS cache %w", err)
	}
	pm.Server = server.NewServer(pm, manager)
	pm.eventCache = eventcache.New(pm.Server, pm.dns)
	pm.execCache = execcache.New(pm.Server, pm.dns)

	tlsGrpc = tls.New(pm.eventCache)
	layer3Grpc = layer3.New(ciliumState, pm.dns, pm.eventCache, enableCilium)
	dnsGrpc = dnsproto.New(ciliumState, pm.dns, pm.eventCache, enableCilium)
	httpGrpc = httpproto.New(ciliumState, pm.dns, pm.eventCache, enableCilium)
	tracingGrpc = tracing.New(ciliumState, pm.dns, pm.eventCache, enableCilium, enableProcessCred, enableProcessNs)

	if enableProcessAncestors {
		execGrpc = execAncestors.New(pm.execCache, pm.eventCache, enableProcessCred, enableProcessNs)
	} else {
		execGrpc = exec.New(pm.execCache, pm.eventCache, enableProcessCred, enableProcessNs)
	}

	logger.GetLogger().WithField("enableCilium", enableCilium).WithFields(logrus.Fields{
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
	case *readyapi.MsgTETRAGONReady:
		// pass
	case *tlsapi.MsgTLSEventUnix:
		processedEvent = tlsGrpc.HandleMessage(msg)
	case *httpapi.MsgHttpEventUnix:
		processedEvent = httpGrpc.HandleHttpMessage(msg)
	case *processapi.MsgExecveEventUnix:
		processedEvent = execGrpc.HandleExecveMessage(msg)
	case *processapi.MsgCloneEventUnix:
		execGrpc.HandleCloneMessage(msg)
	case *networkapi.MsgIPv4EventUnix:
		processedEvent = layer3Grpc.HandleIpMessage(msg)
	case *networkapi.MsgProcessNetworkBurstEventUnix:
		processedEvent = burst.HandleProcessNetworkBurstMessage(msg)
	case *networkapi.MsgInterfaceEventUnix:
		processedEvent = iface.HandleInterfaceMessage(msg)
	case *dnsapi.MsgIPv4DnsUnix:
		processedEvent = dnsGrpc.HandleDnsMessage(msg)
	case *processapi.MsgExitEventUnix:
		processedEvent = execGrpc.HandleExitMessage(msg)
	case *kfreeapi.MsgKfreeSkbUnix:
		processedEvent = kfree.HandleKfreeSkbMessage(msg)
	case *tracingapi.MsgGenericKprobeUnix:
		processedEvent = tracingGrpc.HandleGenericKprobeMessage(msg)
	case *tracingapi.MsgGenericTracepointUnix:
		processedEvent = tracingGrpc.HandleGenericTracepointMessage(msg)
	case *testapi.MsgTestEventUnix:
		processedEvent = test.HandleTestMessage(msg)

	default:
		logger.GetLogger().WithField("event", event).Warnf("unhandled event of type %T", msg)
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
