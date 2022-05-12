//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package burstEventsPoll

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/logger"
	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/ktime"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/timer"
	"github.com/yalue/native_endian"
)

const (
	ProcessNetworkBurstMapName      = "pn_burst_map"
	ProcessNetworkBurstStatsMapName = "pn_burst_map_stats"

	PROCESS_NETWORK_BURST_PROTO_SHIFT   = 48
	PROCESS_NETWORK_BURST_PROCESS_MASK  = 0xffffffff
	PROCESS_NETWORK_BURST_KEY_DIR_SHIFT = 32
	PROCESS_NETWORK_BURST_MSG_DIR_SHIFT = 16
)

var (
	pollTimer = timer.NewPeriodicTimer("Burst event poll", checkAndAddBurstEndEvents, true)
	burstMap  *ebpf.Map
)

type ProcessNetworkBurstKey struct {
	Key uint64
}

type ProcessNetworkBurstValue struct {
	ProcessStartTime uint64
	HistVol          uint64
	WinVol           uint64
	LastWinVol       uint64
	LastPacketTime   uint64
	Burst            uint64
	BurstWindowSize  uint64
}

func PidToBurstKey(pid uint32, protocol uint64, send uint64) uint64 {
	return uint64(pid) | (protocol << PROCESS_NETWORK_BURST_PROTO_SHIFT) | ((send & 1) << PROCESS_NETWORK_BURST_KEY_DIR_SHIFT)
}

func msgToProcessNetworkBurstUnix(m *api.MsgProcessNetworkBurstEvent) *api.MsgProcessNetworkBurstEventUnix {
	return m
}

func HandleProcessNetworkBurst(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgProcessNetworkBurstEvent{}
	err := binary.Read(r, native_endian.NativeEndian(), &m)
	if err != nil {
		return nil, err
	}
	msgUnix := msgToProcessNetworkBurstUnix(&m)
	return []observer.Event{msgUnix}, nil
}

func Start(spec *v1alpha1.TracingPolicySpec) {
	if !spec.Parser.BurstPoll.Enable {
		return
	}
	var err error
	// open map, allowing for it to be not immediately ready
	burstMapFile := filepath.Join(bpf.MapPrefixPath(), ProcessNetworkBurstMapName)
	burstMap, err = ebpf.LoadPinnedMap(burstMapFile, nil)
	for err != nil {
		time.Sleep(100 * time.Millisecond)
		burstMap, err = ebpf.LoadPinnedMap(burstMapFile, nil)
	}

	pollTimer.Start(time.Duration(spec.Parser.BurstPoll.Interval) * time.Millisecond)
}

func Stop() {
	pollTimer.Stop()
}

func checkAndAddBurstEndEvents() {
	var (
		burstLogKey   ProcessNetworkBurstKey
		burstLogValue ProcessNetworkBurstValue
	)

	burstLogEntries := burstMap.Iterate()

	for burstLogEntries.Next(&burstLogKey, &burstLogValue) {
		if checkBurstLog(&burstLogKey, &burstLogValue) {
			// Update entry
			burstLogValue.Burst = 0
			err := burstMap.Update(&burstLogKey, &burstLogValue, ebpf.UpdateExist)
			if err != nil {
				logger.GetLogger().WithError(err).Warn("Could not update burst log")
			}
		}
	}
}

func checkBurstLog(burstLogKey *ProcessNetworkBurstKey, burstLogValue *ProcessNetworkBurstValue) bool {
	if burstLogValue.Burst == 0 {
		return false
	}
	timeSinceLastPacket, err := ktime.NanoTimeSince(int64(burstLogValue.LastPacketTime))
	if err != nil {
		return false
	}
	if timeSinceLastPacket < time.Duration(burstLogValue.BurstWindowSize)*time.Millisecond {
		return false
	}
	// Send burst end event
	createBurstEndEvent(burstLogKey, burstLogValue, timeSinceLastPacket)
	return true
}

func createBurstEndEvent(key *ProcessNetworkBurstKey, value *ProcessNetworkBurstValue, timeSinceLastPacket time.Duration) {
	m := api.MsgProcessNetworkBurstEvent{}
	m.Common.Op = ops.MSG_OP_IPV4_PROCESS_BURST
	m.Common.Size = api.MsgUnixSize
	m.Common.Ktime = value.LastPacketTime + uint64(timeSinceLastPacket)
	m.ProcessKey.Pid = uint32(key.Key & PROCESS_NETWORK_BURST_PROCESS_MASK)
	m.ProcessKey.Ktime = value.ProcessStartTime
	m.Protocol = uint32(key.Key >> PROCESS_NETWORK_BURST_PROTO_SHIFT)
	m.BurstStartDir = uint32(((key.Key >> PROCESS_NETWORK_BURST_KEY_DIR_SHIFT) & 1) << PROCESS_NETWORK_BURST_MSG_DIR_SHIFT)
	m.WindowSize = value.BurstWindowSize
	m.HistAvg = (value.HistVol + value.LastWinVol + value.WinVol) * 1000000000 / (m.Common.Ktime - value.ProcessStartTime)
	m.HistTrigger = 0
	m.WindowAvg = 0

	msgUnix := msgToProcessNetworkBurstUnix(&m)
	observer.AllListeners(msgUnix)
}
