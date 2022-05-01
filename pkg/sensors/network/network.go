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
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/timer"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/vishvananda/netlink"

	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/grpc/iface"
)

var (
	NetworkStatInterval = time.Duration(10 * time.Second)
	sandboxToContainer  = make(map[string]string)
	eventTimer          = timer.NewPeriodicTimer("Network Interface Timer", runNetworkCB, true)
	pollTimer           = timer.NewPeriodicTimer("Network Event Poll", runNetworkBPFGC, true)

	NetworkMapName = "network_map"
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
}

func (k *networkInfoKey) String() string {
	return fmt.Sprintf("Index=%d NetNS: %d", k.Index, k.Netns)
}
func (k *networkInfoKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *networkInfoKey) NewValue() bpf.MapValue {
	return &networkInfoValue{}
}
func (k *networkInfoKey) DeepCopyMapKey() bpf.MapKey {
	return &networkInfoKey{
		Index: k.Index,
		Netns: k.Netns,
	}
}

func (v *networkInfoValue) String() string {
	return fmt.Sprintf(
		"Name=%s: TX=%d:%d RX:%d:%d",
		v.Name, v.TxBytes, v.PacketsOut, v.RxBytes, v.PacketsIn)
}

func (v *networkInfoValue) GetValuePtr() unsafe.Pointer {
	return unsafe.Pointer(&v)
}
func (v *networkInfoValue) DeepCopyMapValue() bpf.MapValue {
	var newV networkInfoValue
	newV = *v
	return &newV
}

func emitInterfaceEvent(attrs *netlink.LinkAttrs, netns string, netnsFilePath string) {
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

	netns := fmt.Sprintf("%d", netKey.Netns)
	name := ""
	txBytes := uint64(0)
	rxBytes := uint64(0)
	pktsOut := uint64(0)
	pktsIn := uint64(0)

	for _, percpu_val := range netValue {
		txBytes += percpu_val.TxBytes
		rxBytes += percpu_val.RxBytes
		pktsOut += percpu_val.PacketsOut
		pktsIn += percpu_val.PacketsIn

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
			Netns: netns,
		},
		Stats: api.MsgInterfaceStats{
			BytesSent:       txBytes,
			BytesReceived:   rxBytes,
			PacketsSent:     pktsOut,
			PacketsReceived: pktsIn,
		},
	}
	observer.AllListeners(&unix)
}

func runNetworkBPFGC() {
	path := filepath.Join(bpf.MapPrefixPath(), NetworkMapName)
	fd, err := bpf.ObjGet(path)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Network GC failed to open file")
		return
	}

	networkMap, err := ebpf.NewMapFromFD(fd)
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

	nsDir, err := ioutil.ReadDir(defaults.NetnsDir)
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

func (net *networkSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return nil
}

func unloadNetworkSensor() error {
	eventTimer.Stop()
	return nil
}

var (
	DevQueueXmit = program.Builder(
		"bpf_dev_queue_xmit.o",
		"dev_queue_xmit",
		"kprobe/dev_queue_xmit",
		"kprobe_dev_queue_xmit",
		"kprobe")
	IngressSkb = program.Builder(
		"bpf_dev_queue_xmit.o",
		"netif_receive_skb",
		"kprobe/netif_receive_skb",
		"kprobe_netif_receive_skb",
		"kprobe",
	)

	NetworkMap = program.MapBuilder(NetworkMapName, DevQueueXmit)
)

func EnableNetworkParser(bpf bool, statInterval uint32) *sensors.Sensor {
	var defaultCBInterval time.Duration

	if statInterval == 0 {
		defaultCBInterval = NetworkStatInterval
	} else {
		defaultCBInterval = time.Duration(time.Duration(statInterval) * time.Second)
	}

	logger.GetLogger().Infof("Enable Interface Statistics")
	if bpf {
		versionStr := "__networkPacket_probe__"
		progs := []*program.Program{
			DevQueueXmit,
			IngressSkb,
		}
		maps := []*program.Map{
			NetworkMap,
		}
		pollTimer.Start(time.Duration(defaultCBInterval))
		return sensors.SensorBuilder(versionStr, progs, maps)
	}
	err := populateSandboxToContainer()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Interface statistics running without containerID info")
	}

	eventTimer.Start(defaultCBInterval)
	return &sensors.Sensor{
		Name:       "interface-sensor",
		UnloadHook: unloadNetworkSensor,
	}
}

func (net *networkSensor) SpecHandler(raw interface{}) (*sensors.Sensor, error) {
	spec := raw.(*v1alpha1.TracingPolicySpec)
	if !spec.Parser.Interface.Enable {
		return nil, nil
	}
	return EnableNetworkParser(spec.Parser.Interface.Packet, spec.Parser.Interface.StatsInterval), nil
}

func init() {
	AddNetwork()
}

func AddNetwork() {
	net := &networkSensor{
		name: "Interface sensor",
	}
	sensors.RegisterProbeType("interface_sensor", net)
	sensors.RegisterTracingSensorsAtInit(net.name, net)
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
