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

	lru "github.com/hashicorp/golang-lru"
	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
	"github.com/yalue/native_endian"

	"github.com/sirupsen/logrus"
)

var (
	UdpGCIntervalDefault = time.Duration(60 * time.Second)
	UdpDeleteInterval    = time.Duration(600 * time.Second)
	UdpMapName           = "udp_map"
	UdpRetprobeMapName   = "udp_retprobe_map"

	mapDir = "/sys/fs/bpf/tcpmon"

	stats          *lru.Cache
	stataCacheSize = 32000
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

	InetRecv = sensors.ProgramBuilder(
		"bpf_inet_send.o",
		"inet_recv",
		"inet_recv",
		"cgroup_skb/ingress",
		"cgroup_skb_ingress",

		false,
		true,
		"cgrp_ingress",
	)

	UdpSend = sensors.ProgramBuilder(
		"bpf_udp_sendmsg.o",
		"udp_sendmsg",
		"udp_sendmsg",
		"kprobe/udp_sendmsg",
		"kprobe_udp_sendmsg",

		false,
		true,
		"kprobe",
	)

	UdpRetSend = sensors.ProgramBuilder(
		"bpf_udp_sendmsg.o",
		"udp_sendmsg",
		"udp_sendmsg",
		"kretprobe/udp_sendmsg",
		"kretprobe_udp_sendmsg",

		true,
		true,
		"kprobe",
	)

	UdpRecv = sensors.ProgramBuilder(
		"bpf_udp_sendmsg.o",
		"skb_consume_udp",
		"skb_consume_udp",
		"kprobe/skb_consume_udp",
		"kprobe_skb_consume_udp",

		false,
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
		ipSrc, k.SPort, ipDst, api.SwapByte(k.DPort), k.Cookie)
}
func (k *udpInfoKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
func (k *udpInfoKey) NewValue() bpf.MapValue {
	return &udpInfoValue{}
}
func (k *udpInfoKey) DeepCopyMapKey() bpf.MapKey {
	return &udpInfoKey{
		SAddr:   k.SAddr,
		DAddr:   k.DAddr,
		DPort:   k.DPort,
		SPort:   k.SPort,
		Cookie:  k.Cookie,
		Padding: 0,
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
	unix.SockCookie = k.Cookie
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

func udpDiffValues(key *udpInfoKey, last, curr *udpInfoValue) udpInfoValue {
	if curr.TXBytes < last.TXBytes {
		logger.GetLogger().Warnf("key %s\n    curr %s < last %s\n", key, curr, last)
	}
	return udpInfoValue{
		TXBytes:  curr.TXBytes - last.TXBytes,
		RXBytes:  curr.RXBytes - last.RXBytes,
		SegsIn:   curr.SegsIn - last.SegsIn,
		SegsOut:  curr.SegsOut - last.SegsOut,
		SkDrops:  curr.SkDrops - last.SkDrops,
		Ktime:    curr.Ktime,
		PidKtime: curr.PidKtime,
		Pid:      curr.Pid,
	}
}

func udpGcCb(m *bpf.Map, k bpf.MapKey, v bpf.MapValue) {
	udpValue := v.(*udpInfoValue)
	udpKey := k.(*udpInfoKey)

	// When FGS starts we add cookies to sockets as we see
	// them. But, for some time after starting its possible
	// that the IP hooks see flows without a cookie. At
	// this point the flow is not unique and as a result we
	// may end up accumulating bytes in the wrong buckets.
	// Instead lets simply omit these metrics. Note, we
	// never unload our socket cookie stamper program so
	// restarts will not cause this condition.
	if udpKey.Cookie == 0 {
		return
	}

	t, err := reader.NanoTimeSince(int64(udpValue.Ktime))
	if err != nil {
		logger.GetLogger().WithError(err).WithField("time", udpValue.Ktime).Warn("UDP NanoTimeSince failed.")
		return
	}

	entry, ok := stats.Get(*udpKey)
	if ok {
		last := entry.(udpInfoValue)
		if *udpValue != last {
			diffValue := udpDiffValues(udpKey, &last, udpValue)
			mapUpdate := v.DeepCopyMapValue().(*udpInfoValue)
			udpKey = k.DeepCopyMapKey().(*udpInfoKey)
			stats.Add(*udpKey, *mapUpdate)
			emitStatEvent(udpKey, &diffValue)
		}
	} else {
		udpValue = v.DeepCopyMapValue().(*udpInfoValue)
		stats.Add(*udpKey, *udpValue)
		emitStatEvent(udpKey, udpValue)
	}

	if t > UdpDeleteInterval {
		stats.Remove(*udpKey)
		m.DeleteKey(k)
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

func EnableUdpParser(cgroup bool, interval time.Duration) *sensors.Sensor {
	var progs []*sensors.Program
	var maps []*sensors.Map
	var versionStr string

	if !kernels.MinKernelVersion("5.10.0") || !cgroup {
		progs = []*sensors.Program{
			UdpSend,
			UdpRetSend,
			UdpRecv,
		}
		maps = []*sensors.Map{
			UdpMapKprobe,
			UdpRetprobeMap,
		}
		versionStr = "__udp_sensor_probe__"
	} else {
		progs = []*sensors.Program{
			SockCreate,
			InetSend,
			InetRecv,
		}
		maps = []*sensors.Map{
			SocketCookieMap,
			UdpMap,
		}
		versionStr = "__udp_sensor_cgroup__"
	}
	udpGC(interval)
	logger.GetLogger().WithFields(logrus.Fields{
		"sensorName":     versionStr,
		"statsInterval":  interval,
		"deleteInterval": UdpDeleteInterval,
	}).Infof("Enable UDP")
	return sensors.SensorBuilder(versionStr, progs, maps)
}

func (parser *udpSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
	var interval = time.Duration(UdpGCIntervalDefault)

	if !spec.Parser.Udp.Enable {
		return nil, nil
	}
	if spec.Parser.Udp.StatsInterval > 0 {
		interval = time.Duration(spec.Parser.Udp.StatsInterval) * time.Second
	}
	if spec.Parser.Udp.DeleteIdleSocketInterval > 0 {
		UdpDeleteInterval = time.Duration(spec.Parser.Udp.DeleteIdleSocketInterval) * time.Second
	}
	return EnableUdpParser(spec.Parser.Udp.Cgroup, interval), nil
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
	var err error

	stats, err = lru.New(stataCacheSize)
	if err != nil {
		logger.GetLogger().WithError(err).Errorf("UDP cache failed. Disabling UDP")
		return
	}

	udp := &udpSensor{
		name: "UDP sensor",
	}
	sensors.RegisterProbeType("udp_sensor", udp)
	sensors.RegisterTracingSensorsAtInit(udp.name, udp)
	observer.RegisterEventHandlerAtInit(api.MSG_OP_IPV4_UDPCONNECT, handleUdpConnect)
}
