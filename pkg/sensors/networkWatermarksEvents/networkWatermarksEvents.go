//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package networkWatermarksEvents

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/timer"

	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/grpc/networkWatermarks"

	"github.com/yalue/native_endian"
)

const (
	ProcessNetworkWatermarksMapName      = "pn_watermarks_map"
	ProcessNetworkWatermarksStatsMapName = "pn_watermarks_map_stats"

	PROCESS_NETWORK_WATERMARKS_PROTO_SHIFT   = 48
	PROCESS_NETWORK_WATERMARKS_PROCESS_MASK  = 0xffffffff
	PROCESS_NETWORK_WATERMARKS_KEY_DIR_SHIFT = 32
	PROCESS_NETWORK_WATERMARKS_MSG_DIR_SHIFT = 16
	WATERMARKS_INGRESS                       = 0
	WATERMARKS_EGRESS                        = 1
	WATERMARKS_END                           = 0
	WATERMARKS_START                         = 1
	WATERMARKS_BURST                         = 0
	WATERMARKS_DIP                           = 1
	WATERMARKS_STATE_BURST                   = 1
	WATERMARKS_STATE_DIP                     = 2
)

var (
	watermarksExitTimer = timer.NewPeriodicTimer("Network watermarks event exit gen", checkAndAddWatermarksEndEvents, true)
	watermarksMap       *ebpf.Map
	refCount            = 0
	refCountMu          sync.Mutex
	legacyBurst         = make(map[uint32]bool)
)

type ProcessNetworkWatermarksKey struct {
	Key uint64
}

type ProcessNetworkWatermarksValue struct {
	ProcessStartTime     uint64
	HistVol              uint64
	WinVol               uint64
	LastWinVol           uint64
	LastPacketTime       uint64
	WatermarksState      uint64
	WatermarksWindowSize uint64
}

func PidToWatermarksKey(pid uint32, protocol uint64, send uint64) uint64 {
	return uint64(pid) | (protocol << PROCESS_NETWORK_WATERMARKS_PROTO_SHIFT) | ((send & 1) << PROCESS_NETWORK_WATERMARKS_KEY_DIR_SHIFT)
}

func msgToProcessNetworkWatermarksUnix(m *api.MsgProcessNetworkWatermarkEvent) *networkWatermarks.MsgProcessNetworkWatermarksEventUnix {
	return &networkWatermarks.MsgProcessNetworkWatermarksEventUnix{MsgProcessNetworkWatermarkEvent: *m}
}

func HandleProcessNetworkWatermarks(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgProcessNetworkWatermarkEvent{}
	err := binary.Read(r, native_endian.NativeEndian(), &m)
	if err != nil {
		return nil, err
	}
	msgUnix := msgToProcessNetworkWatermarksUnix(&m)
	if legacyBurst[msgUnix.Protocol] {
		msgUnix.Common.Op = ops.MSG_OP_PROCESS_NETWORK_BURST
	}
	return []observer.Event{msgUnix}, nil
}

func Start(spec *v1alpha1.TracingPolicySpec, protocol uint32, legacy bool) {
	if spec.Parser.NetworkWatermarksExitGen.Enable {
		var err error
		refCountMu.Lock()
		defer refCountMu.Unlock()
		// open map, allowing for it to be not immediately ready
		watermarksMapFile := filepath.Join(bpf.MapPrefixPath(), ProcessNetworkWatermarksMapName)
		watermarksMap, err = ebpf.LoadPinnedMap(watermarksMapFile, nil)
		for err != nil {
			time.Sleep(100 * time.Millisecond)
			watermarksMap, err = ebpf.LoadPinnedMap(watermarksMapFile, nil)
		}

		// Attempting to start an already running timer is a NOP.
		watermarksExitTimer.Start(time.Duration(spec.Parser.NetworkWatermarksExitGen.Interval) * time.Millisecond)
		refCount++
	} else if spec.Parser.BurstExitGen.Enable {
		var err error
		refCountMu.Lock()
		defer refCountMu.Unlock()
		// open map, allowing for it to be not immediately ready
		watermarksMapFile := filepath.Join(bpf.MapPrefixPath(), ProcessNetworkWatermarksMapName)
		watermarksMap, err = ebpf.LoadPinnedMap(watermarksMapFile, nil)
		for err != nil {
			time.Sleep(100 * time.Millisecond)
			watermarksMap, err = ebpf.LoadPinnedMap(watermarksMapFile, nil)
		}

		// Attempting to start an already running timer is a NOP.
		watermarksExitTimer.Start(time.Duration(spec.Parser.BurstExitGen.Interval) * time.Millisecond)
		refCount++
	}
	// Default to sending Watermark events instead of Burst events, but if a config only uses legacy burst entries,
	// then we will send legacy burst events instead of watermarks events. Any use of watermark entries in the config
	// implies the user is aware of watermarks events, so we switch to sending them instead.
	if legacy {
		legacyBurst[protocol] = true
	} else {
		delete(legacyBurst, protocol)
	}
}

func Stop(protocol uint32) {
	// We reference count the number of sensors that start and stop the watermarksEvent exit generator
	// and only stop it if the count reaches 0.
	refCountMu.Lock()
	defer refCountMu.Unlock()
	if refCount > 0 {
		refCount--
	}
	if refCount == 0 {
		watermarksExitTimer.Stop()
	}
	delete(legacyBurst, protocol)
}

func checkAndAddWatermarksEndEvents() {
	var (
		watermarksLogKey   ProcessNetworkWatermarksKey
		watermarksLogValue ProcessNetworkWatermarksValue
	)

	if watermarksMap == nil {
		logger.GetLogger().Warn("Nil watermarks map, skipping watermarks update round")
		return
	}

	watermarksLogEntries := watermarksMap.Iterate()

	for watermarksLogEntries.Next(&watermarksLogKey, &watermarksLogValue) {
		if checkWatermarksLog(&watermarksLogKey, &watermarksLogValue) {
			// Update entry
			watermarksLogValue.WatermarksState = 0
			err := watermarksMap.Update(&watermarksLogKey, &watermarksLogValue, ebpf.UpdateExist)
			if err != nil {
				logger.GetLogger().WithError(err).Warn("Could not update watermarks log")
			}
		}
	}
}

func checkWatermarksLog(watermarksLogKey *ProcessNetworkWatermarksKey, watermarksLogValue *ProcessNetworkWatermarksValue) bool {
	if watermarksLogValue.WatermarksState == 0 {
		return false
	}
	timeSinceLastPacket, err := ktime.NanoTimeSince(int64(watermarksLogValue.LastPacketTime))
	if err != nil {
		return false
	}
	if timeSinceLastPacket < time.Duration(watermarksLogValue.WatermarksWindowSize)*time.Millisecond {
		return false
	}
	// Send network watermarks end event
	createWatermarksEndEvent(watermarksLogKey, watermarksLogValue, timeSinceLastPacket)
	return true
}

func createWatermarksEndEvent(key *ProcessNetworkWatermarksKey, value *ProcessNetworkWatermarksValue, timeSinceLastPacket time.Duration) {
	m := api.MsgProcessNetworkWatermarkEvent{}
	m.Common.Op = ops.MSG_OP_PROCESS_NETWORK_WATERMARK
	m.Common.Size = api.MsgUnixSize
	m.Common.Ktime = value.LastPacketTime + uint64(timeSinceLastPacket)
	m.ProcessKey.Pid = uint32(key.Key & PROCESS_NETWORK_WATERMARKS_PROCESS_MASK)
	m.ProcessKey.Ktime = value.ProcessStartTime
	m.Protocol = uint32(key.Key >> PROCESS_NETWORK_WATERMARKS_PROTO_SHIFT)
	m.Direction = uint8((key.Key >> PROCESS_NETWORK_WATERMARKS_KEY_DIR_SHIFT) & 1)
	m.State = WATERMARKS_END
	if value.WatermarksState == WATERMARKS_STATE_BURST {
		m.Type = WATERMARKS_BURST
	} else {
		m.Type = WATERMARKS_DIP
	}
	m.WindowSize = value.WatermarksWindowSize
	m.HistAvg = (value.HistVol + value.LastWinVol + value.WinVol) * 1000000000 / (m.Common.Ktime - value.ProcessStartTime)
	m.HistBurstTrigger = 0
	m.HistDipTrigger = 0
	m.WindowAvg = 0

	msgUnix := msgToProcessNetworkWatermarksUnix(&m)
	observer.AllListeners(msgUnix)
}
