//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package network

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/timer"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/vishvananda/netlink"

	"github.com/cilium/tetragon/api/v1/tetragon"

	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/grpc/iface"
	"github.com/isovalent/hubble-fgs/pkg/nscache"
)

var (
	NetworkStatInterval = time.Duration(10 * time.Second)
	eventTimer          = timer.NewPeriodicTimer("Network Interface Timer", runNetworkCB, true)
)

func emitInterfaceEvent(attrs *netlink.LinkAttrs, netns uint64, pod *tetragon.Pod) {
	name := ""
	if pod != nil {
		name = pod.Container.Name
	}
	unix := iface.MsgInterfaceEventUnix{
		Common: processapi.MsgCommon{
			Op:    ops.MSG_OP_INTERFACE_STATS,
			Size:  1,
			Ktime: 0,
		},
		Iface: api.MsgInterface{
			Index:         attrs.Index,
			Name:          attrs.Name,
			Netns:         netns,
			ContainerName: name,
		},
		Stats: api.MsgInterfaceStats{
			BytesSent:       attrs.Statistics.TxBytes,
			BytesReceived:   attrs.Statistics.RxBytes,
			PacketsSent:     attrs.Statistics.TxPackets,
			PacketsReceived: attrs.Statistics.RxPackets,
			TxErrors:        attrs.Statistics.TxErrors,
			RxErrors:        attrs.Statistics.RxErrors,
			TxDrops:         attrs.Statistics.TxDropped,
			RxDrops:         attrs.Statistics.RxDropped,
		},
	}
	observer.AllListeners(&unix)
}

func runNetworkCB() {
	links, err := netlink.LinkList()
	if err != nil {
		logger.GetLogger().Info("Link list failed", logfields.Error, err)
	} else {
		for _, l := range links {
			emitInterfaceEvent(l.Attrs(), 0, nil)
		}
	}

	emitNSEvent()
}

type networkSensor struct {
	name string
}

func (net *networkSensor) LoadProbe(_ sensors.LoadProbeArgs) error {
	return nil
}

func unloadNetworkSensor() error {
	eventTimer.Stop()
	return nil
}

var (
	ExitNs = program.Builder(
		"bpf_net_ns_net_exit.o",
		"net_ns_net_exit",
		"kprobe/net_ns_net_exit",
		"tg_net_ns_net_exit",
		"kprobe",
	)
)

func EnableNetworkParser(policy tracingpolicy.TracingPolicy, statInterval uint32) *sensors.Sensor {
	var defaultCBInterval time.Duration
	var progs []*program.Program
	var maps []*program.Map

	if statInterval == 0 {
		defaultCBInterval = NetworkStatInterval
	} else {
		defaultCBInterval = time.Duration(time.Duration(statInterval) * time.Second)
	}

	versionStr := "__networkPacket_probe__"
	logger.GetLogger().Info("Enable Polling Interface Statistics")
	progs = []*program.Program{
		ExitNs,
	}
	maps = []*program.Map{}
	eventTimer.Start(defaultCBInterval)

	sens := sensors.SensorBuilder(policy, versionStr, progs, maps)
	sens.PreUnloadHook = unloadNetworkSensor

	return sens
}

func (net *networkSensor) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	fid policyfilter.PolicyID,
) (sensors.SensorIface, error) {
	spec := policy.TpSpec()
	if !spec.Parser.Interface.Enable {
		return nil, nil
	}

	if fid != policyfilter.NoFilterID {
		return nil, fmt.Errorf("parser interface sensor does not implement policy filtering")
	}

	if spec.Parser.Interface.Packet {
		logger.GetLogger().Info("Interface sensor: beta packet option has been deprecated; using polling approach instead.")
	}
	return EnableNetworkParser(policy, spec.Parser.Interface.StatsInterval), nil
}

type MsgNetNsExitEvent struct {
	Common processapi.MsgCommon
	NsInum uint64
}

func handleNetNsExit(r *bytes.Reader) ([]observer.Event, error) {
	m := MsgNetNsExitEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, fmt.Errorf("failed to read netns exit operation: %w", err)
	}
	nscache.DelNetNs(m.NsInum)
	return nil, nil
}

func init() {
	AddNetwork()
}

func AddNetwork() {
	net := &networkSensor{
		name: "Interface sensor",
	}
	sensors.RegisterProbeType("interface_sensor", net)
	sensors.RegisterPolicyHandlerAtInit(net.name, net)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_NETNS_EXIT, handleNetNsExit)
}
