// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package exec

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/api/dataapi"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/cgidmap"
	"github.com/cilium/tetragon/pkg/cgrouprate"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/observer"
	ossoption "github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/exec/userinfo"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/strutils"

	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/grpc/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/exec/procevents"
)

func msgToExecveUnix(m *processapi.MsgExecveEvent) *exec.MsgExecveEventUnix {
	unix := &exec.MsgExecveEventUnix{}
	unix.Unix = &processapi.MsgExecveEventUnix{}
	unix.Unix.Msg = *m
	return unix
}

func msgToExecveKubeUnix(m *processapi.MsgExecveEvent, exec_id string, filename string) processapi.MsgK8sUnix {
	kube := processapi.MsgK8sUnix{
		Cgrpid:        m.Kube.Cgrpid,
		CgrpTrackerID: m.Kube.CgrpTrackerID,
	}

	// If cgidmap is enabled, resolve the container id using the cgroup id and the cgroup
	// tracker id.
	if ossoption.Config.EnableCgIDmap {
		cgidmap.SetContainerID(&kube)
		return kube
	}

	// The first byte is set to zero if there is no docker ID for this event.
	if m.Kube.Docker[0] != 0x00 {
		// We always get a null terminated buffer from bpf
		cgroup := cgroups.CgroupNameFromCStr(m.Kube.Docker[:processapi.CGROUP_NAME_LENGTH])
		docker, _ := procevents.LookupContainerId(cgroup, true, false)
		if docker != "" {
			kube.Docker = docker
			logger.Trace(logger.GetLogger(), "process_exec: container ID set successfully",
				"cgroup.id", m.Kube.Cgrpid,
				"cgroup.name", cgroup,
				"docker", kube.Docker,
				"process.exec_id", exec_id,
				"process.binary", filename)
		} else {
			logger.Trace(logger.GetLogger(), "process_exec: no container ID due to cgroup name not being a compatible ID, ignoring.",
				"cgroup.name", cgroup,
				"cgroup.id", m.Kube.Cgrpid,
				"process.exec_id", exec_id,
				"process.binary", filename)
		}
	} else {
		logger.Trace(logger.GetLogger(), "process_exec: no container ID due to cgroup name being empty, ignoring.",
			"cgroup.id", m.Kube.Cgrpid, "process.exec_id", exec_id, "process.binary", filename)
	}

	return kube
}

// TODO(rafaelroquetto): the read*() functions below also exist in upstream
// OSS. Perhaps parts of the code can be exported and shared.
const (
	errorNoMem = "<enomem>"
)

func readData(reader *bytes.Reader, size uint16) ([]byte, error) {
	var desc dataapi.DataEventDesc

	if uint16(unsafe.Sizeof(desc)) != size {
		return nil, errors.New("msg exec mismatched size")
	}
	if err := binary.Read(reader, binary.LittleEndian, &desc); err != nil {
		return nil, err
	}
	return observer.DataGet(desc)
}

func readRawBytes(reader *bytes.Reader, exec *processapi.MsgExec, size uint16, flags uint32) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}

	if exec.Flags&flags != 0 {
		data, err := readData(reader, size)
		if err != nil {
			return nil, err
		}

		return data, nil
	}

	data := make([]byte, size)

	nread, err := reader.Read(data)
	if err != nil {
		return nil, err
	}

	if nread != int(size) {
		return nil, errors.New("size mismatch")
	}

	return data, nil
}

func resolveArgs(reader *bytes.Reader, exec *processapi.MsgExec) (string, error) {
	if exec.SizeArgs == 0 {
		return "", nil
	}

	data, err := readRawBytes(reader, exec, exec.SizeArgs, api.EventDataArgs)
	if err != nil {
		return "", err
	}

	if exec.Flags&api.EventDataArgs != 0 && len(data) > 0 && data[len(data)-1] == '\x00' {
		data = data[:len(data)-1]
	}

	if len(data) == 0 {
		return "", nil
	}

	size := 0
	numArgs := 0

	for arg := range bytes.SplitSeq(data, []byte{'\x00'}) {
		numArgs++

		if len(arg) == 0 {
			size += 2
			continue
		}

		size += len(arg)

		if bytes.Contains(arg, []byte{' '}) {
			size += 2
		}
	}

	if numArgs > 1 {
		size += numArgs - 1
	}

	var args strings.Builder
	args.Grow(size)

	for arg := range bytes.SplitSeq(data, []byte{'\x00'}) {
		if args.Len() > 0 {
			args.WriteByte(' ')
		}

		if len(arg) == 0 {
			args.WriteString(`""`)
			continue
		}

		hasWhiteSpace := bytes.Contains(arg, []byte{' '})

		if hasWhiteSpace {
			args.WriteByte('"')
		}

		strutils.WriteUTF8FromBPFBytes(&args, arg)

		if hasWhiteSpace {
			args.WriteByte('"')
		}
	}

	return args.String(), nil
}

func resolveCwd(reader *bytes.Reader, exec *processapi.MsgExec) (string, error) {
	var cwd []byte

	if exec.SizeCwd > 0 {
		cwd = make([]byte, exec.SizeCwd)

		nread, err := reader.Read(cwd)
		if err != nil {
			return "", err
		}

		if nread != int(exec.SizeCwd) {
			return "", errors.New("cwd size mismatch")
		}
	}

	if (exec.Flags & api.EventNoCWDSupport) != 0 {
		return "", nil
	} else if (exec.Flags & api.EventErrorCWD) != 0 {
		return "", nil
	} else if (exec.Flags & api.EventRootCWD) != 0 {
		return "/", nil
	}

	if len(cwd) == 0 {
		return "", nil
	}

	return strutils.UTF8FromBPFBytes(cwd), nil
}

func resolveFilename(reader *bytes.Reader, exec *processapi.MsgExec) (string, error) {
	if exec.SizePath == 0 {
		return errorNoMem, nil
	}

	data, err := readRawBytes(reader, exec, exec.SizePath, api.EventDataFilename)
	if err != nil {
		return "", err
	}

	return strutils.UTF8FromBPFBytes(data), nil
}

func resolveProcEnvs(reader *bytes.Reader, exec *processapi.MsgExec) ([]string, error) {
	if exec.SizeEnvs == 0 {
		return nil, nil
	}

	data, err := readRawBytes(reader, exec, exec.SizeEnvs, api.EventDataEnvs)
	if err != nil {
		return nil, err
	}

	// cut the zero byte
	if data[len(data)-1] == '\x00' {
		data = data[:len(data)-1]
	}

	var ret []string

	for v := range bytes.SplitSeq(data, []byte{0}) {
		ret = append(ret, strutils.UTF8FromBPFBytes(v))
	}

	return ret, nil
}

func execParse(reader *bytes.Reader) (processapi.MsgProcess, error) {
	proc := processapi.MsgProcess{
		Filename: errorNoMem,
		Args:     errorNoMem,
		Cwd:      errorNoMem,
		Size:     processapi.MSG_SIZEOF_EXECVE,
	}
	exec := processapi.MsgExec{}

	if err := binary.Read(reader, binary.LittleEndian, &exec); err != nil {
		logger.GetLogger().Debug("Failed to read exec event", logfields.Error, err)
		return proc, err
	}

	proc.PID = exec.PID
	proc.TID = exec.TID
	proc.NSPID = exec.NSPID
	proc.UID = exec.UID
	proc.Flags = exec.Flags
	proc.Ktime = exec.Ktime
	proc.AUID = exec.AUID
	proc.SecureExec = exec.SecureExec

	size := exec.Size - processapi.MSG_SIZEOF_EXECVE
	if size > processapi.MSG_SIZEOF_BUFFER-processapi.MSG_SIZEOF_EXECVE {
		err := fmt.Errorf("msg exec size larger than argsbuffer")
		return proc, err
	}

	if size != uint32(exec.SizePath+exec.SizeArgs+exec.SizeCwd+exec.SizeEnvs) {
		err := fmt.Errorf("msg exec size larger than argsbuffer, size %d != %d, SizePath %d, SizeArgs %d, SizeCwd %d, SizeEnvs %d",
			size, exec.SizePath+exec.SizeArgs+exec.SizeCwd, exec.SizePath, exec.SizeArgs, exec.SizeCwd, exec.SizeEnvs)
		return proc, err
	}

	filename, err := resolveFilename(reader, &exec)
	if err != nil {
		return proc, err
	}

	proc.Filename = filename

	arguments, err := resolveArgs(reader, &exec)
	if err != nil {
		return proc, err
	}

	proc.Args = arguments

	cwd, err := resolveCwd(reader, &exec)
	if err != nil {
		return proc, err
	}

	proc.Cwd = cwd

	envs, err := resolveProcEnvs(reader, &exec)
	if err != nil {
		return proc, err
	}

	proc.Envs = envs

	proc.Size = exec.Size
	return proc, nil
}

func handleExecve(r *bytes.Reader) ([]observer.Event, error) {
	m := processapi.MsgExecveEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	msgUnix := msgToExecveUnix(&m)
	msgUnix.Unix.Process, err = execParse(r)
	if err == nil {
		err = userinfo.MsgToExecveAccountUnix(msgUnix.Unix)
		if err != nil {
			logger.Trace(logger.GetLogger(), "Resolving process uid to username record failed", logfields.Error, err,
				"process.pid", msgUnix.Unix.Process.PID,
				"process.binary", msgUnix.Unix.Process.Filename,
				"process.uid", msgUnix.Unix.Process.UID)
		}
	}
	msgUnix.Unix.Kube = msgToExecveKubeUnix(&m, process.GetExecID(&msgUnix.Unix.Process), msgUnix.Unix.Process.Filename)
	return []observer.Event{msgUnix}, nil
}

func msgToExitUnix(m *processapi.MsgExitEvent) *exec.MsgExitEventUnix {
	return &exec.MsgExitEventUnix{MsgExitEvent: *m}
}

func handleExit(r *bytes.Reader) ([]observer.Event, error) {
	m := processapi.MsgExitEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	msgUnix := msgToExitUnix(&m)
	return []observer.Event{msgUnix}, nil
}

func handleClone(r *bytes.Reader) ([]observer.Event, error) {
	m := processapi.MsgCloneEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	msgUnix := &exec.MsgCloneEventUnix{MsgCloneEvent: m}
	return []observer.Event{msgUnix}, nil
}

func handleThrottleEvent(r *bytes.Reader) ([]observer.Event, error) {
	m := processapi.MsgThrottleEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		return nil, err
	}
	cgrouprate.Check(&m.Kube, m.Common.Ktime)
	return nil, nil
}

type execSensor struct {
	name string
}

func (e *execSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return program.LoadRawTracepointProgram(args.BPFDir, args.Load, args.Maps, args.Verbose)
}

func init() {
	AddExec()
}

func AddExec() {
	execveProbe := &execSensor{
		name: "exec base sensor",
	}
	sensors.RegisterProbeType("execve", execveProbe)

	observer.RegisterEventHandlerAtInit(ops.MSG_OP_EXECVE, handleExecve)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_EXIT, handleExit)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_CLONE, handleClone)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_THROTTLE, handleThrottleEvent)
}
