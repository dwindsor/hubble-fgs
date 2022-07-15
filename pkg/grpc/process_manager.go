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
	"context"
	"fmt"
	"sync"

	"github.com/cilium/hubble/pkg/cilium"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/eventcache"
	"github.com/isovalent/hubble-fgs/pkg/execcache"
	"github.com/isovalent/hubble-fgs/pkg/grpc/dnsproto"
	"github.com/isovalent/hubble-fgs/pkg/grpc/exec"
	"github.com/isovalent/hubble-fgs/pkg/grpc/execAncestors"
	"github.com/isovalent/hubble-fgs/pkg/grpc/file"
	"github.com/isovalent/hubble-fgs/pkg/grpc/httpproto"
	"github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	"github.com/isovalent/hubble-fgs/pkg/grpc/tls"
	"github.com/isovalent/hubble-fgs/pkg/grpc/tracing"
	"github.com/isovalent/hubble-fgs/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/server"
	"github.com/sirupsen/logrus"
)

var (
	tlsGrpc     *tls.Grpc
	layer3Grpc  *layer3.Grpc
	dnsGrpc     *dnsproto.Grpc
	httpGrpc    *httpproto.Grpc
	tracingGrpc *tracing.Grpc
	fileGrpc    *file.Grpc
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
	ctx context.Context,
	wg *sync.WaitGroup,
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
	pm.Server = server.NewServer(ctx, wg, pm, manager)
	pm.eventCache = eventcache.New(pm.Server, pm.dns)
	pm.execCache = execcache.New(pm.Server, pm.dns)

	tlsGrpc = tls.New(pm.eventCache)
	layer3Grpc = layer3.New(ciliumState, pm.dns, pm.eventCache, enableCilium)
	dnsGrpc = dnsproto.New(ciliumState, pm.dns, pm.eventCache, enableCilium)
	httpGrpc = httpproto.New(ciliumState, pm.dns, pm.eventCache, enableCilium)
	tracingGrpc = tracing.New(ciliumState, pm.dns, pm.eventCache, enableCilium, enableProcessCred, enableProcessNs)
	fileGrpc = file.New(ciliumState, pm.dns, pm.eventCache, enableCilium, enableProcessCred, enableProcessNs)

	if enableProcessAncestors {
		execAncestors.New(pm.execCache, pm.eventCache, enableProcessCred, enableProcessNs)
	} else {
		exec.New(pm.execCache, pm.eventCache, enableProcessCred, enableProcessNs)
	}

	logger.GetLogger().WithField("enableCilium", enableCilium).WithFields(logrus.Fields{
		"enableEventCache":  enableEventCache,
		"enableProcessCred": enableProcessCred,
		"enableProcessNs":   enableProcessNs,
	}).Info("Starting process manager")
	return pm, nil
}

// Notify implements Listener.Notify.
func (pm *ProcessManager) Notify(event notify.Interface) error {
	processedEvent := event.HandleMessage()
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

func (pm *ProcessManager) NotifyListener(original interface{}, processed *tetragon.GetEventsResponse) {
	pm.mux.Lock()
	defer pm.mux.Unlock()
	for l := range pm.listeners {
		l.Notify(processed)
	}
	eventmetrics.ProcessEvent(original, processed)
}
