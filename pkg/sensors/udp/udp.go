//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package udp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
	"github.com/yalue/native_endian"
)

var (
	UdpGCIntervalDefault = time.Duration(60 * time.Second)
	UdpStatInterval      = time.Duration(60 * time.Second)
	UdpDeleteInterval    = time.Duration(60 * time.Second)
	UdpMapName           = "udp_map"
	UdpRetprobeMapName   = "udp_retprobe_map"

	mapDir = "/sys/fs/bpf/tcpmon"
)

var (
	SockCreate = sensors.ProgramBuilder(
		"bpf_sock.o",
		"sock_create",
		"sock_create",
		"cgroup/sock_create",
		"cgroup_sock_create",

		false,
		true,
		"cgrp_socket")

	InetSend = sensors.ProgramBuilder(
		"bpf_inet_send.o",
		"inet_send",
		"inet_send",
		"cgroup_skb/egress",
		"cgroup_skb_egress",

		false,
		true,
		"cgrp_egress",
	)

	UdpSend = sensors.ProgramBuilder(
		"bpf_udp_sendmsg.o",
		"udp_sendmsg",
		"udp_sendmsg",
		"kprobe/udp_sendmsg",
		"kprobe/udp_sendmsg",

		false,
		true,
		"kprobe",
	)

	UdpRetSend = sensors.ProgramBuilder(
		"bpf_udp_sendmsg.o",
		"udp_sendmsg",
		"udp_sendmsg",
		"kretprobe/udp_sendmsg",
		"kpretrobe/udp_sendmsg",

		true,
		true,
		"kprobe",
	)
	SocketCookieMap = sensors.MapBuilder("socket_cookie_to_proc_map", "", &sensors.TCPConnect)
	UdpMap          = sensors.MapBuilder(UdpMapName, "", InetSend)
	UdpMapKprobe    = sensors.MapBuilder(UdpMapName, "", UdpSend)
	UdpRetprobeMap  = sensors.MapBuilder(UdpRetprobeMapName, "", UdpSend)
)

type udpInfoKey struct {
	Cookie  uint64
	SAddr   uint32
	DAddr   uint32
	SPort   uint16
	DPort   uint16
	Padding uint32
}

type udpInfoValue struct {
	TXBytes  uint64
	RXBytes  uint64
	SegsIn   uint64
	SegsOut  uint64
	Ktime    uint64
	PidKtime uint64
	Pid      uint32
	SkDrops  uint32
}

func (k *udpInfoKey) String() string {
	ipDst := reader.GetIP(k.DAddr, api.MSG_OP_IPV4_UDPCONNECT)
	ipSrc := reader.GetIP(k.SAddr, api.MSG_OP_IPV4_UDPCONNECT)
	return fmt.Sprintf("SAddr=%s:%d DAddr=%s:%d Cookie=%d",
		ipSrc, api.SwapByte(k.SPort), ipDst, api.SwapByte(k.DPort), k.Cookie)
}
func (k *udpInfoKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *udpInfoKey) NewValue() bpf.MapValue {
	return &udpInfoValue{}
}
func (k *udpInfoKey) DeepCopyMapKey() bpf.MapKey {
	return &udpInfoKey{
		SAddr:  k.SAddr,
		DAddr:  k.DAddr,
		DPort:  k.DPort,
		SPort:  k.SPort,
		Cookie: k.Cookie,
	}
}

func (v *udpInfoValue) String() string {
	return fmt.Sprintf(
		"Pid: %d Ktime %d\n"+
			"TXBytes: %d RXBytes%d\n"+
			"SegsOut: %d SegsIn: %d\n"+
			"SkDrops: %d\n",
		v.Pid, v.Ktime,
		v.TXBytes, v.RXBytes, v.SegsOut, v.SegsIn, v.SkDrops)
}
func (s *udpInfoValue) GetValuePtr() unsafe.Pointer {
	return unsafe.Pointer(&s)
}
func (s *udpInfoValue) DeepCopyMapValue() bpf.MapValue {
	var v udpInfoValue
	v = *s
	return &v
}

func emitStatEvent(k *udpInfoKey, v *udpInfoValue) {
	unix := api.MsgIPv4EventUnix{}

	unix.Common = api.MsgCommon{
		Op:    api.MSG_OP_IPV4_UDPSTATS,
		Size:  1,
		Ktime: v.Ktime,
	}
	unix.Tuple = api.MsgIPv4Tuple{
		SAddr: k.SAddr,
		DAddr: k.DAddr,
		SPort: k.SPort,
		DPort: k.DPort,
		Proto: 0,
	}
	unix.Return = 0
	unix.ProcessKey = api.MsgExecveKey{
		Pid:   v.Pid,
		Ktime: v.PidKtime,
	}
	unix.SocketStats = api.MsgSocketStats{
		BytesSent:     v.TXBytes,
		BytesReceived: v.RXBytes,
		SegsIn:        uint32(v.SegsIn),
		SegsOut:       uint32(v.SegsOut),
		SkDrop:        v.SkDrops,
	}
	observer.AllListeners(&unix)
	return
}

func udpGcCb(m *bpf.Map, k bpf.MapKey, v bpf.MapValue) {
	udpValue := v.(*udpInfoValue)
	t, err := reader.NanoTimeSince(int64(udpValue.Ktime))
	if err != nil {
		return
	}

	if t > UdpDeleteInterval {
		m.DeleteKey(k)
	}
	if t <= UdpStatInterval {
		emitStatEvent(k.(*udpInfoKey), v.(*udpInfoValue))
	}
}

func runUdpGC() {
	file := filepath.Join(mapDir, UdpMapName)

	m, err := bpf.OpenMap(file)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", file).Warn("UDP GC failed to open file")
		return
	}
	defer m.Close()
	m.MapKey = &udpInfoKey{}
	m.KeySize = 24
	m.MapValue = &udpInfoValue{}
	m.DumpWithCallback(udpGcCb)
}

func udpGC(gcInterval time.Duration) {
	ticker := time.NewTicker(gcInterval)
	go func() {
		for {
			select {
			case <-ticker.C:
				runUdpGC()
			}
		}
	}()
}

type udpSensor struct {
	name string
}

func (udp *udpSensor) LoadProbe(args sensors.LoadProbeArgs) (error, int) {
	return nil, 0
}

func EnableUdpParser() *sensors.Sensor {
	var progs []*sensors.Program
	var maps []*sensors.Map
	defaultGCInterval := UdpGCIntervalDefault

	logger.GetLogger().Infof("Enable UDP")
	if !kernels.MinKernelVersion("5.10.0") {
		progs = []*sensors.Program{
			UdpSend,
			UdpRetSend,
		}
		maps = []*sensors.Map{
			UdpMapKprobe,
			UdpRetprobeMap,
		}
	} else {
		progs = []*sensors.Program{
			SockCreate,
			InetSend,
		}
		maps = []*sensors.Map{
			SocketCookieMap,
			UdpMap,
		}
	}
	udpGC(defaultGCInterval)
	return sensors.SensorBuilder("__udp_sensor__", progs, maps)
}

func (parser *udpSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
	if !spec.Parser.Udp.Enable {
		return nil, nil
	}
	return EnableUdpParser(), nil
}

func handleUdpConnect(r *bytes.Reader) ([]observer.ObserverEvent, error) {
	m := api.MsgIPv4Event{}
	err := binary.Read(r, native_endian.NativeEndian(), &m)
	if err != nil {
		return nil, err
	}
	msgUnix := observer.MsgToIPv4Unix(&m)
	return []observer.ObserverEvent{msgUnix}, nil
}

func init() {
	AddUDP()
}

func AddUDP() {
	udp := &udpSensor{
		name: "UDP sensor",
	}
	sensors.RegisterProbeType("udp_sensor", udp)
	sensors.RegisterTracingSensorsAtInit(udp.name, udp)
	observer.RegisterEventHandlerAtInit(api.MSG_OP_IPV4_UDPCONNECT, handleUdpConnect)
}
