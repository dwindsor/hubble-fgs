//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tcp

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
)

const (
	TCP_PROC_STATE_LISTEN = 10

	maxMapRetries = 4
	mapRetryDelay = 1
)

type SocketMapKey struct {
	Saddr     uint32
	Daddr     uint32
	Dport     uint16
	Sport     uint16
	Remaining uint32
	Uid       uint64
}

type SocketMapValue struct {
	Pid     uint32 `align:"key"`
	Pad1    uint32
	Ktime   uint64
	ZeroWin uint32 `align:"zero_window"`
	SFlags  uint32 `align:"socket_flags"`
}

func bpfIpToString(ip uint32) string {
	scratch := make(net.IP, 4)

	scratch[0] = byte(ip)
	scratch[1] = byte(ip >> 8)
	scratch[2] = byte(ip >> 16)
	scratch[3] = byte(ip >> 24)

	return scratch.String()
}

func (k *SocketMapKey) String() string {
	return fmt.Sprintf("%s:%d %s:%d meta(uid %d, remaining %d)",
		bpfIpToString(k.Saddr), k.Sport,
		bpfIpToString(k.Daddr), k.Dport,
		k.Uid, k.Remaining)
}
func (k *SocketMapKey) NewValue() bpf.MapValue     { return &SocketMapValue{} }
func (k *SocketMapKey) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(k) }
func (k *SocketMapKey) DeepCopyMapKey() bpf.MapKey { return &SocketMapKey{} }

func (v *SocketMapValue) String() string {
	return fmt.Sprintf("%d %d", v.Pid, v.Ktime)
}
func (v *SocketMapValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *SocketMapValue) DeepCopyMapValue() bpf.MapValue {
	return &SocketMapValue{}
}

func writeSockMap(tcp *layer3.MsgIPEventUnix, m *bpf.Map, uid uint64) {
	key := &SocketMapKey{
		Saddr:     uint32(tcp.Tuple.SAddr[0]),
		Daddr:     uint32(tcp.Tuple.DAddr[0]),
		Dport:     tcp.Tuple.DPort,
		Sport:     tcp.Tuple.SPort,
		Remaining: 0,
		Uid:       uid,
	}

	val := &SocketMapValue{
		Pid:     tcp.ProcessKey.Pid,
		Pad1:    0,
		Ktime:   tcp.ProcessKey.Ktime,
		ZeroWin: 0,
		SFlags:  0,
	}
	m.Update(key, val)
}
