// Copyright 2019 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package observer

import (
	"github.com/covalentio/hubble-fgs/pkg/bpf"
	"github.com/covalentio/hubble-fgs/pkg/defaults"
	"github.com/covalentio/hubble-fgs/pkg/logger"

	"bytes"
	"context"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
)

var (
	ObserverExecve__program   string
	observerExecve__attach    = "__x64_sys_execve"
	observerExecve__label     = "kprobe/__x64_sys_execve"
	observerExecve__prog      = "kprobe_execve"
	observerExecve__map       = "kprobe_execve_map"
	observerExecve__map_label = "execve_map"

	ObserverTCPConnect__program   string
	observerTCPConnect__attach    = "tcp_connect"
	observerTCPConnect__label     = "kprobe/tcp_connect"
	observerTCPConnect__prog      = "kprobe_tcp_connect"
	observerTCPConnect__map       = "kprobe_tcp_events"
	observerTCPConnect__map_label = "tcpmon_map"

	observerTimeout = 5 * time.Minute
	execTimeout     = 5 * time.Minute
	pollTimeout     = 5000

	log *zap.Logger
)

func getIP(i uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, i)
	return ip
}

func swapByte(b uint16) uint16 {
	return (b << 8) | (b >> 8)
}

func observerIPV4TCPConnectPrinter(msg *bpf.MsgIPv4TcpConnect) {
	var args []string

	for i := 0; i < 4; i++ {
		str := strings.Trim(string(msg.Pid.Args[i][:]), "\u0000")
		if str == "" {
			continue
		}
		args = append(args, str)
	}

	log.Debug("KprobeEvent",
		zap.Uint32("pid", msg.Pid.PID),
		zap.Uint32("uid", msg.Pid.UID),
		zap.String("prog", strings.Trim(string(msg.Pid.Filename[:]), "\u0000")),
		zap.Strings("args", args),
		zap.Uint8("proto", msg.Tuple.Proto),
		zap.String("saddr", getIP(msg.Tuple.SAddr).String()),
		zap.Uint16("sport", msg.Tuple.SPort),
		zap.String("daddr", getIP(msg.Tuple.DAddr).String()),
		zap.Uint16("dport", swapByte(msg.Tuple.DPort)),
	)
}

func (k *ObserverKprobe) ObserverReceiver() error {
	conn, err := net.Dial("unix", defaults.DefaultUnixSock)

	if err != nil {
		return err
	}

	for {
		dec := gob.NewDecoder(conn)
		var IPv4TCPConnectMsg bpf.MsgIPv4TcpConnect

		err = dec.Decode(&IPv4TCPConnectMsg)
		if err != nil {
			return err
		}

		observerIPV4TCPConnectPrinter(&IPv4TCPConnectMsg)
	}
}

func (k *ObserverKprobe) observerListeners(msg *bpf.MsgIPv4TcpConnect) {
	for _, c := range k.listeners {
		enc := gob.NewEncoder(c)
		if err := enc.Encode(msg); err != nil {
			log.Warn("Write failure")
		}
	}
}

func (k *ObserverKprobe) AddListener(conn net.Conn) {
	k.listeners = append(k.listeners, conn)
}

func (k *ObserverKprobe) RemoveListener(conn net.Conn) {
	for i, c := range k.listeners {
		if c == conn {
			fmt.Printf("delete listener %v\n", conn)
			k.listeners = append(k.listeners[:i], k.listeners[i+1:]...)
		}
		fmt.Printf("walking listener %v\n", c)
	}
}

func (k *ObserverKprobe) receiveEvent(msg *bpf.PerfEventSample, cpu int) {
	data := msg.DataCopy()
	var op uint8 = data[0]

	switch op {
	case bpf.MSG_OP_IPV4_TCPCONNECT:
		m := bpf.MsgIPv4TcpConnect{}
		err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &m)
		if err != nil {
			panic(err)
		}
		observerIPV4TCPConnectPrinter(&m)
		k.observerListeners(&m)
	}
}

func observerLost(msg *bpf.PerfEventLost, cpu int) {
	fmt.Printf("msg -- event lost\n")
}

func observerError(msg *bpf.PerfEvent) {
	fmt.Printf("msg -- event error\n")
}

func isCtxDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func (k *ObserverKprobe) observerLoadExecve(stopCtx context.Context) error {
	err, execve_fd := bpf.LoadKprobe(
		ObserverExecve__program,
		observerExecve__attach,
		observerExecve__label,
		k.bpfDir+observerExecve__prog,
		k.bpfDir+observerExecve__map,
		observerExecve__map_label, 0)
	if err != nil {
		return fmt.Errorf("failed kprobe execve LoadKprobe: %s\n", err)
	}
	k.execve_fd = execve_fd
	return nil
}

func (k *ObserverKprobe) observerLoadEvents(stopCtx context.Context) error {
	err, _ := bpf.LoadKprobe(
		ObserverTCPConnect__program,
		observerTCPConnect__attach,
		observerTCPConnect__label,
		k.bpfDir+observerTCPConnect__prog,
		k.bpfDir+observerTCPConnect__map,
		observerTCPConnect__map_label,
		k.execve_fd)
	if err != nil {
		return fmt.Errorf("failed kprobe events LoadKprobe: %s\n", err)
	}

	c := bpf.DefaultPerfEventConfig()
	e, err := bpf.NewPerCpuEvents(c)
	if err != nil {
		return fmt.Errorf("failed kprobe events NewPerCpuEvents: %s\n", err)
	}
	defer e.CloseAll()

	receiveEvent := k.receiveEvent

	for !isCtxDone(stopCtx) {
		todo, err := e.Poll(pollTimeout)
		switch {
		case isCtxDone(stopCtx):
			return nil

		case err == syscall.EBADF:
			return fmt.Errorf("kprobe events syscall.EBADF: %s", err)

		case err != nil:
			log.Warn("kprobe events poll: ", zap.Error(err))
			continue
		}
		if todo > 0 {
			if err := e.ReadAll(receiveEvent, observerLost, observerError); err != nil {
				log.Warn("kprobe events read: ", zap.Error(err))
			}
		}
	}
	return nil
}

func (k *ObserverKprobe) createDir() {
	os.Mkdir(k.bpfDir, os.ModeDir)
}

type ObserverKprobe struct {
	bpfDir    string
	execve_fd int
	listeners []net.Conn
}

func (k *ObserverKprobe) Start() {
	k.createDir()
	k.observerLoadExecve(context.TODO())
	k.observerLoadEvents(context.TODO()) // events must be last to load to link with maps
}

func NewObserverKprobe(bpfDir string) *ObserverKprobe {
	log = logger.GetLogger()
	return &ObserverKprobe{
		bpfDir: bpfDir,
	}
}
