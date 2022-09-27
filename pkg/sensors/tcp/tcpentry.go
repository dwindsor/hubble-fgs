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
	Cookie uint64
}

type SocketMapValue struct {
	Pid      uint32 `align:"key"`
	Pad1     uint32
	Ktime    uint64
	ZeroWin  uint32 `align:"zero_window"`
	SFlags   uint32 `align:"socket_flags"`
	LastTime uint64
	Sent     uint64
	Received uint64
	Buckets  [8]uint64
}

func (k *SocketMapKey) String() string {
	return fmt.Sprintf("%d", k.Cookie)
}
func (k *SocketMapKey) NewValue() bpf.MapValue     { return &SocketMapValue{} }
func (k *SocketMapKey) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(k) }
func (k *SocketMapKey) DeepCopyMapKey() bpf.MapKey { return &SocketMapKey{Cookie: k.Cookie} }

func (v *SocketMapValue) String() string {
	return fmt.Sprintf("%d %d", v.Pid, v.Ktime)
}
func (v *SocketMapValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *SocketMapValue) DeepCopyMapValue() bpf.MapValue {
	return &SocketMapValue{}
}

func writeSockMap(tcp *layer3.MsgIPEventUnix, m *bpf.Map, uid uint64) {
	key := &SocketMapKey{
		Cookie: tcp.SockCookie,
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
