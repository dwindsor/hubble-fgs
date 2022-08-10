package iface

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/reader/notify"
	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/metrics/eventmetrics"
	"github.com/isovalent/hubble-fgs/pkg/nscache"
)

var (
	nodeName = node.GetNodeNameForExport()
)

func statsToHistogram(h api.Histogram) *tetragon.Histogram {
	bucket99 := &tetragon.HistogramBucket{
		Percentile: 99,
		Size:       1,
		Count:      h.B99,
	}
	bucket90 := &tetragon.HistogramBucket{
		Percentile: 90,
		Size:       9,
		Count:      h.B90,
	}
	bucket75 := &tetragon.HistogramBucket{
		Percentile: 75,
		Size:       15,
		Count:      h.B75,
	}
	bucket50 := &tetragon.HistogramBucket{
		Percentile: 50,
		Size:       25,
		Count:      h.B50,
	}
	bucket25 := &tetragon.HistogramBucket{
		Percentile: 25,
		Size:       25,
		Count:      h.B25,
	}
	bucket10 := &tetragon.HistogramBucket{
		Percentile: 10,
		Size:       15,
		Count:      h.B10,
	}
	bucket01 := &tetragon.HistogramBucket{
		Percentile: 1,
		Size:       9,
		Count:      h.B01,
	}
	bucket00 := &tetragon.HistogramBucket{
		Percentile: 0,
		Size:       1,
		Count:      h.B00,
	}

	buckets := []*tetragon.HistogramBucket{
		bucket00,
		bucket01,
		bucket10,
		bucket25,
		bucket50,
		bucket75,
		bucket90,
		bucket99,
	}
	return &tetragon.Histogram{
		Buckets: buckets,
	}
}

func (msg *MsgInterfaceEventUnix) getInterfaceStats() *tetragon.InterfaceStats {
	pod, _ := nscache.GetPod(msg.Iface.Netns)
	netns := fmt.Sprintf("%d", msg.Iface.Netns)
	fgsEvent := &tetragon.InterfaceStats{
		InterfaceName:    msg.Iface.Name,
		InterfaceIfindex: uint32(msg.Iface.Index),
		Netns:            netns,
		ContainerName:    msg.Iface.ContainerName,
		BytesSent:        msg.Stats.BytesSent,
		BytesReceived:    msg.Stats.BytesReceived,
		PacketsSent:      msg.Stats.PacketsSent,
		PacketsReceived:  msg.Stats.PacketsReceived,
		TxErrors:         msg.Stats.TxErrors,
		RxErrors:         msg.Stats.RxErrors,
		TxDrops:          msg.Stats.TxDrops,
		RxDrops:          msg.Stats.RxDrops,
		Pod:              pod,
		Qlen:             statsToHistogram(msg.Stats.Qlen),
	}
	eventmetrics.HandleInterfaceStatsEvent(fgsEvent)
	return fgsEvent
}

type MsgInterfaceEventUnix struct {
	Common processapi.MsgCommon
	Kube   processapi.MsgK8sUnix
	Iface  api.MsgInterface
	Stats  api.MsgInterfaceStats
}

func (msg *MsgInterfaceEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	return eventcache.HandleGenericInternal(ev, timestamp)
}

func (msg *MsgInterfaceEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev)
}

func (msg *MsgInterfaceEventUnix) Notify() bool {
	return true
}

func (msg *MsgInterfaceEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	switch msg.Common.Op {
	case ops.MSG_OP_INTERFACE_STATS:
		stats := msg.getInterfaceStats()
		if stats != nil {
			res = &tetragon.GetEventsResponse{
				Event:    &tetragon.GetEventsResponse_InterfaceStats{InterfaceStats: stats},
				NodeName: nodeName,
				Time:     ktime.ToProto(msg.Common.Ktime),
			}
		}
	default:
		logger.GetLogger().WithField("message", msg).Warn("HandleInterfaceMessage: Unhandled event")
	}
	return res
}

func (msg *MsgInterfaceEventUnix) Cast(o interface{}) notify.Message {
	return &MsgInterfaceEventUnix{}
}
