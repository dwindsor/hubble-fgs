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
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/timer"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/vishvananda/netlink"

	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/grpc/iface"
	"github.com/isovalent/hubble-fgs/pkg/nscache"
)

var (
	NetworkStatInterval = time.Duration(10 * time.Second)
	sandboxToContainer  = make(map[string]string)
	eventTimer          = timer.NewPeriodicTimer("Network Interface Timer", runNetworkCB, true)
	pollTimer           = timer.NewPeriodicTimer("Network Event Poll", runNetworkBPFGC, true)

	NetworkMapName = "network_map"
	bpfEnabled     = false
)

type networkInfoKey struct {
	Index uint64
	Netns uint64
}

type networkInfoValue struct {
	Name       [16]byte
	TxBytes    uint64
	RxBytes    uint64
	PacketsOut uint64
	PacketsIn  uint64

	TxDrops uint32
	Pad     uint32

	// Embedded Qdisc histogram
	P99     uint64
	P90     uint64
	P75     uint64
	P50     uint64
	P25     uint64
	P10     uint64
	P01     uint64
	P00     uint64
	QLenSum uint64
}

func (k *networkInfoKey) String() string {
	return fmt.Sprintf("Index=%d NetNS: %d", k.Index, k.Netns)
}

func (v *networkInfoValue) String() string {
	return fmt.Sprintf(
		"Name=%s: TX=%d:%d RX:%d:%d",
		v.Name, v.TxBytes, v.PacketsOut, v.RxBytes, v.PacketsIn)
}

func emitInterfaceEvent(attrs *netlink.LinkAttrs, netns string, netnsFilePath string) {
	n, _ := strconv.ParseUint(netns, 10, 64)
	unix := iface.MsgInterfaceEventUnix{
		Common: processapi.MsgCommon{
			Op:    ops.MSG_OP_INTERFACE_STATS,
			Size:  1,
			Ktime: 0,
		},
		Iface: api.MsgInterface{
			Index:         attrs.Index,
			Name:          attrs.Name,
			Netns:         n,
			ContainerName: getContainerName(netnsFilePath),
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

func nameParse(b [16]byte) (string, int) {
	s := ""
	for i, hex := range b {
		if hex == 0 {
			return s, i
		}
		c := fmt.Sprintf("%c", hex)
		s += c
	}
	return s, 16
}

func networkGcCb(netKey *networkInfoKey, netValue []networkInfoValue) {
	foundName := false
	name := ""
	txBytes := uint64(0)
	rxBytes := uint64(0)
	pktsOut := uint64(0)
	pktsIn := uint64(0)
	txDrops := uint32(0)

	qlen := api.Histogram{
		B99: 0,
		B90: 0,
		B75: 0,
		B50: 0,
		B25: 0,
		B10: 0,
		B01: 0,
		B00: 0,
		Sum: 0,
	}

	for _, percpu_val := range netValue {
		txBytes += percpu_val.TxBytes
		rxBytes += percpu_val.RxBytes
		pktsOut += percpu_val.PacketsOut
		pktsIn += percpu_val.PacketsIn
		txDrops += percpu_val.TxDrops

		qlen.B99 += percpu_val.P99
		qlen.B90 += percpu_val.P90
		qlen.B75 += percpu_val.P75
		qlen.B50 += percpu_val.P50
		qlen.B50 += percpu_val.P50
		qlen.B25 += percpu_val.P25
		qlen.B10 += percpu_val.P10
		qlen.B01 += percpu_val.P01
		qlen.B00 += percpu_val.P00
		qlen.Sum += percpu_val.QLenSum

		// These are duplicated in each value at the moment
		if !foundName {
			n, l := nameParse(percpu_val.Name)
			if l > 0 {
				foundName = true
				name = n
			}
		}
	}

	unix := iface.MsgInterfaceEventUnix{
		Common: processapi.MsgCommon{
			Op:    ops.MSG_OP_INTERFACE_STATS,
			Size:  1,
			Ktime: 0,
		},
		Iface: api.MsgInterface{
			Index: int(netKey.Index),
			Name:  string(name),
			Netns: netKey.Netns,
		},
		Stats: api.MsgInterfaceStats{
			BytesSent:       txBytes,
			BytesReceived:   rxBytes,
			PacketsSent:     pktsOut,
			PacketsReceived: pktsIn,
			Qlen:            qlen,
			TxDrops:         uint64(txDrops),
		},
	}
	observer.AllListeners(&unix)
}

func runNetworkBPFGC() {
	path := filepath.Join(bpf.MapPrefixPath(), NetworkMapName)
	networkMap, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Network map open failed")
		return
	}

	var (
		key networkInfoKey
		val []networkInfoValue
	)
	iter := networkMap.Iterate()
	for iter.Next(&key, &val) {
		networkGcCb(&key, val)
	}

	networkMap.Close()
}

func runNetworkCB() {
	links, err := netlink.LinkList()
	if err != nil {
		logger.GetLogger().WithError(err).Infof("Link list failed")
	} else {
		for _, l := range links {
			emitInterfaceEvent(l.Attrs(), "", "")
		}
	}

	nsDir, err := os.ReadDir(defaults.NetnsDir)
	if err != nil {
		return
	}

	for fileIndex := range nsDir {
		nsFile := nsDir[fileIndex]
		nsFileName := filepath.Join(defaults.NetnsDir, nsFile.Name())

		netns, err := ns.GetNS(nsFileName)
		if err != nil {
			logger.GetLogger().WithField("pid", os.Getpid()).WithField("file", nsFileName).WithError(err).Infof("GetNS from path failed")
			continue
		}
		defer netns.Close()

		err = netns.Do(func(_ ns.NetNS) error {
			links, err = netlink.LinkList()
			if err != nil {
				logger.GetLogger().WithField("pid", os.Getpid()).WithField("file", nsFileName).WithError(err).Infof("netns LinkList failed")
				return fmt.Errorf("Netlink LinkList() error: %v", err)
			}
			for _, l := range links {
				emitInterfaceEvent(l.Attrs(), nsFile.Name(), nsFileName)
			}
			return nil
		})
	}
}

type networkSensor struct {
	name string
}

func (net *networkSensor) LoadProbe(_ sensors.LoadProbeArgs) error {
	return nil
}

func unloadNetworkSensor() error {
	if bpfEnabled {
		pollTimer.Stop()
	} else {
		eventTimer.Stop()
	}
	return nil
}

var (
	DevQueueXmit = program.Builder(
		"bpf_dev_queue_xmit.o",
		"__dev_queue_xmit",
		"kprobe/dev_queue_xmit",
		"tg_dev_queue_xmit",
		"kprobe")
	IngressSkb = program.Builder(
		"bpf_dev_queue_xmit.o",
		"netif_receive_skb",
		"kprobe/netif_receive_skb",
		"tg_netif_receive_skb",
		"kprobe",
	)
	IngressGro = program.Builder(
		"bpf_dev_queue_xmit.o",
		"napi_gro_receive",
		"kprobe/napi_gro_receive",
		"tg_napi_gro_receive",
		"kprobe",
	)
	NetifRxInternal = program.Builder(
		"bpf_dev_queue_xmit.o",
		"netif_rx",
		"kprobe/__netif_rx",
		"tg_netif_rx",
		"kprobe",
	)
	UnregisterNetdev = program.Builder(
		"bpf_dev_queue_xmit.o",
		"call_netdevice_notifiers_info",
		"kprobe/call_netdevice_notifiers_info",
		"tg_call_netdevice_notifiers_info",
		"kprobe",
	)
	ExitNs = program.Builder(
		"bpf_dev_queue_xmit.o",
		"net_ns_net_exit",
		"kprobe/net_ns_net_exit",
		"tg_net_ns_net_exit",
		"kprobe",
	)

	NetworkMap = program.MapBuilder(NetworkMapName, DevQueueXmit)
)

func EnableNetworkParser(statInterval uint32) *sensors.Sensor {
	var defaultCBInterval time.Duration
	var progs []*program.Program
	var maps []*program.Map

	if statInterval == 0 {
		defaultCBInterval = NetworkStatInterval
	} else {
		defaultCBInterval = time.Duration(time.Duration(statInterval) * time.Second)
	}

	versionStr := "__networkPacket_probe__"
	if bpfEnabled {
		logger.GetLogger().Infof("Enable Packet Interface Statistics")
		progs = []*program.Program{
			DevQueueXmit,
			//	IngressSkb,
			IngressGro,
			NetifRxInternal,
			UnregisterNetdev,
			ExitNs,
		}
		maps = []*program.Map{
			NetworkMap,
		}
		pollTimer.Start(time.Duration(defaultCBInterval))
	} else {
		logger.GetLogger().Infof("Enable Polling Interface Statistics")
		progs = []*program.Program{
			ExitNs,
		}
		maps = []*program.Map{}

		err := populateSandboxToContainer()
		if err != nil {
			logger.GetLogger().WithError(err).Warn("Interface statistics running without containerID info")
		}

		eventTimer.Start(defaultCBInterval)
	}

	sens := sensors.SensorBuilder(versionStr, progs, maps)
	sens.PreUnloadHook = unloadNetworkSensor

	return sens
}

func (net *networkSensor) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	fid policyfilter.PolicyID,
) (*sensors.Sensor, error) {
	spec := policy.TpSpec()
	if !spec.Parser.Interface.Enable {
		return nil, nil
	}

	if fid != policyfilter.NoFilterID {
		return nil, fmt.Errorf("parser interface sensor does not implement policy filtering")
	}

	bpfEnabled = spec.Parser.Interface.Packet
	return EnableNetworkParser(spec.Parser.Interface.StatsInterval), nil
}

type MsgNetNsExitEvent struct {
	Common processapi.MsgCommon
	NsInum uint64
}

func handleNetNsExit(r *bytes.Reader) ([]observer.Event, error) {
	m := MsgNetNsExitEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, fmt.Errorf("Failed to read netns exit operation: %w", err)
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

func getContainerName(sandboxKey string) string {
	if sandboxKey == "" {
		return ""
	}
	containerName := sandboxToContainer[sandboxKey]
	if containerName == "" {
		err := populateSandboxToContainer()
		if err != nil {
			logger.GetLogger().WithError(err).Debug("get container name failed")
			return ""
		}
		return sandboxToContainer[sandboxKey]
	}
	return containerName
}

func populateSandboxToContainer() error {
	newSandboxToContainer := make(map[string]string)
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		return err
	}

	for _, container := range containers {
		containerDetails, err := cli.ContainerInspect(ctx, container.ID)
		if err != nil {
			logger.GetLogger().WithError(err).WithField("container", container.ID).Warn("container details missing")
		}
		newSandboxToContainer[containerDetails.NetworkSettings.SandboxKey] = containerDetails.Name
	}
	sandboxToContainer = newSandboxToContainer
	return nil
}
