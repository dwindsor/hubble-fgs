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
	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/bpf"
	"github.com/covalentio/hubble-fgs/pkg/logger"
	"github.com/covalentio/hubble-fgs/pkg/reader"

	"bytes"
	"context"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"go.uber.org/zap"
)

const (
	Progsize = 64
	MaxArgs  = 5
	ArgSize  = 32
)

var (
	ProcFS = "/proc/"

	ObserverExecve__program    string
	observerExecve__x64_attach = "__x64_sys_execve"
	observerExecve__attach     = "sys_execve"
	observerExecve__label      = "kprobe/sys_execve"
	observerExecve__prog       = "kprobe_execve"
	observerExecve__map        = "kprobe_execve_map"
	observerExecve__map_label  = "execve_map"

	ObserverExecveat__program    string
	observerExecveat__x64_attach = "__x64_sys_execveat"
	observerExecveat__attach     = "sys_execveat"
	observerExecveat__label      = "kprobe/sys_execveat"
	observerExecveat__prog       = "kprobe_execveat"
	observerExecveat__map        = "kprobe_execve_map"
	observerExecveat__map_label  = "execve_map"

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

func (k *ObserverKprobe) observerListeners(msg *api.MsgIPv4TcpConnect) {
	for _, c := range k.listeners {
		enc := gob.NewEncoder(c)
		if err := enc.Encode(msg); err != nil {
			log.Debug("Write failure", zap.Error(err))
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
	case api.MSG_OP_IPV4_TCPCONNECT:
		m := api.MsgIPv4TcpConnect{}
		err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &m)
		if err != nil {
			panic(err)
		}
		reader.ObserverIPV4TCPConnectPrinter(&m, log)
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
	var execve_fd int
	var err error

	err, execve_fd = bpf.LoadKprobe(
		ObserverExecve__program,
		observerExecve__x64_attach,
		observerExecve__label,
		k.bpfDir+observerExecve__prog,
		k.bpfDir+observerExecve__map,
		observerExecve__map_label, 0)
	if err != nil {
		/* If we fail attach with __x64_sys_execve variant try again with
		 * sys_execve variant.
		 */
		err, execve_fd = bpf.LoadKprobe(
			ObserverExecve__program,
			observerExecve__attach,
			observerExecve__label,
			k.bpfDir+observerExecve__prog,
			k.bpfDir+observerExecve__map,
			observerExecve__map_label, 0)
		if err != nil {
			return fmt.Errorf("failed kprobe execve LoadKprobe: %s\n", err)
		}
	}
	k.execve_fd = execve_fd

	err, _ = bpf.LoadKprobe(
		ObserverExecveat__program,
		observerExecveat__x64_attach,
		observerExecveat__label,
		k.bpfDir+observerExecveat__prog,
		k.bpfDir+observerExecveat__map,
		observerExecveat__map_label,
		k.execve_fd)
	if err != nil {
		/* If we fail attach with __x64_sys_execve variant try again with
		 * sys_execve variant.
		 */
		err, _ = bpf.LoadKprobe(
			ObserverExecveat__program,
			observerExecveat__attach,
			observerExecveat__label,
			k.bpfDir+observerExecveat__prog,
			k.bpfDir+observerExecveat__map,
			observerExecveat__map_label,
			k.execve_fd)
		if err != nil {
			return fmt.Errorf("failed kprobe execve LoadKprobe: %s\n", err)
		}
	}
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

type ObserverProcs struct {
	pid  uint32
	name string
	args []string
}

type ExecveKey struct {
	Pid uint32
}

type ExecveValue struct {
	Pid      uint32
	Filename [Progsize]byte
	Args     [MaxArgs][ArgSize]byte
}

func (k *ExecveKey) String() string             { return fmt.Sprintf("key=%d", k.Pid) }
func (k *ExecveKey) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(k) }
func (k *ExecveKey) NewValue() bpf.MapValue     { return &ExecveValue{} }
func (k *ExecveKey) DeepCopyMapKey() bpf.MapKey { return &ExecveKey{k.Pid} }

func (v *ExecveValue) String() string                 { return fmt.Sprintf("value=%d %s %s", v.Pid, v.Filename, v.Args) }
func (v *ExecveValue) GetValuePtr() unsafe.Pointer    { return unsafe.Pointer(v) }
func (v *ExecveValue) DeepCopyMapValue() bpf.MapValue { return &ExecveValue{Pid: v.Pid} } // TBD

func getRunningProcs() []ObserverProcs {
	var procs []ObserverProcs
	procFS, _ := ioutil.ReadDir(ProcFS)

	for _, d := range procFS {
		if d.IsDir() == false {
			continue
		}
		cmdline, err := ioutil.ReadFile(ProcFS + d.Name() + "/cmdline")
		if err != nil {
			continue
		}
		if string(cmdline) == "" {
			continue
		}

		pid, err := strconv.ParseUint(d.Name(), 10, 32)
		if err != nil {
			continue
		}
		cmds := strings.Split(string(cmdline), "--")
		p := ObserverProcs{pid: uint32(pid), name: cmds[0], args: cmds[1:]}
		procs = append(procs, p)
	}

	m, err := bpf.OpenMap("/sys/fs/bpf/tcpmon/kprobe_execve_map")
	if err != nil {
		panic(err)
	}
	for _, p := range procs {
		k := &ExecveKey{Pid: p.pid}
		v := &ExecveValue{
			Pid: p.pid,
		}
		copy(v.Filename[:], p.name)
		for i, a := range p.args {
			if i < MaxArgs {
				copy(v.Args[i][:], a)
			}
		}
		m.Update(k, v)
	}
	return procs
}

func (k *ObserverKprobe) populateExecve(ctx context.Context) {
	getRunningProcs()
}

type ObserverKprobe struct {
	bpfDir    string
	execve_fd int
	listeners []net.Conn
}

func (k *ObserverKprobe) Start() {
	k.createDir()
	k.observerLoadExecve(context.TODO())
	k.populateExecve(context.TODO())
	k.observerLoadEvents(context.TODO()) // events must be last to load to link with maps
}

func NewObserverKprobe(bpfDir string) *ObserverKprobe {
	log = logger.GetLogger()
	return &ObserverKprobe{
		bpfDir: bpfDir,
	}
}
