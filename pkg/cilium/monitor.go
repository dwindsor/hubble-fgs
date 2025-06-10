// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cilium

import (
	"bytes"
	"context"
	"encoding/gob"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/defaults"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/monitor/payload"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/isovalent/hubble-fgs/pkg/oldhubble/cilium"
)

// returns an error if connect fails, otherwise nil
func handleMonitorSocket(ctx context.Context, log logger.FieldLogger, ciliumState *cilium.State) error {
	conn, err := net.Dial("unix", defaults.MonitorSockPath1_2)
	if err != nil {
		log.Warn("Failed to connect to "+defaults.MonitorSockPath1_2, logfields.Error, err)
		return err
	}

	if err = consumeMonitorEvents(ctx, conn, ciliumState); err != nil {
		log.Warn("Failed to process monitor event. Reconnecting...", logfields.Error, err)
	}
	if err = conn.Close(); err != nil {
		log.Warn("Failed to close "+defaults.MonitorSockPath1_2, logfields.Error, err)
	}

	return nil
}

// HandleMonitorSocket connects to the monitor socket and consumes monitor events.
func HandleMonitorSocket(ctx context.Context, ciliumState *cilium.State) {
	t := 10 * time.Second
	log := logger.GetLogger()
	for {
		if err := handleMonitorSocket(ctx, log, ciliumState); err != nil {
			// connect failure, double timer
			t = 2 * t
		} else {
			t = 10 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(t):
		}
	}
}

func consumeMonitorEvents(ctx context.Context, conn net.Conn, ciliumState *cilium.State) error {
	defer conn.Close()
	var pl payload.Payload
	dec := gob.NewDecoder(conn)
	ipCacheEvents := make(chan monitorAPI.AgentNotify, 100)
	ciliumState.StartMirroringIPCache(ipCacheEvents)
	for {
		if err := pl.DecodeBinary(dec); err != nil {
			return err
		}
		switch pl.Data[0] {
		case monitorAPI.MessageTypeAgent:
			buf := bytes.NewBuffer(pl.Data[1:])
			payloadDecoder := gob.NewDecoder(buf)
			an := monitorAPI.AgentNotify{}
			if err := payloadDecoder.Decode(&an); err != nil {
				logger.GetLogger().Warn("failed to decoded agent notification message", logfields.Error, err)
				continue
			}
			switch an.Type {
			case monitorAPI.AgentNotifyIPCacheUpserted,
				monitorAPI.AgentNotifyIPCacheDeleted:
				ipCacheEvents <- an
			}
		}
		select {
		case <-ctx.Done():
			return nil
		default:
		}
	}
}
