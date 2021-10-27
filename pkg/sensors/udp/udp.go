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

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
	"github.com/yalue/native_endian"
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

	SocketCookieMap = sensors.MapBuilder("socket_cookie_to_proc_map", "", &sensors.TCPConnect)
)

type udpSensor struct {
	name string
}

func (udp *udpSensor) LoadProbe(args sensors.LoadProbeArgs) (error, int) {
	return nil, 0
}

func EnableUdpParser() *sensors.Sensor {
	var progs []*sensors.Program
	var maps []*sensors.Map

	logger.GetLogger().Infof("Enable UDP")
	if !kernels.MinKernelVersion("5.10.0") {
		progs = []*sensors.Program{
			UdpSend,
		}
	} else {
		progs = []*sensors.Program{
			SockCreate,
			InetSend,
		}
		maps = []*sensors.Map{
			SocketCookieMap,
		}
	}
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
