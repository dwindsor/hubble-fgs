// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package procevents

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/cgroups"
	ossExec "github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/caps"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/cilium/tetragon/pkg/sensors/exec/execvemap"
	"github.com/cilium/tetragon/pkg/sensors/exec/userinfo"
	"github.com/cilium/tetragon/pkg/strutils"

	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/grpc/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
)

const (
	maxMapRetries = 4
	mapRetryDelay = 1

	kernelPid = uint32(0)
)

func stringToUTF8(s []byte) []byte {
	var utf8Cursor int
	var i int

	for i < len(s) {
		r, size := utf8.DecodeRune(s[i:])
		utf8Cursor += utf8.EncodeRune(s[utf8Cursor:], r)
		i += size
	}
	return s
}

type procs struct {
	ppid                 uint32
	pnspid               uint32
	pflags               uint32
	pktime               uint64
	uids                 []uint32
	gids                 []uint32
	pid                  uint32
	tid                  uint32
	nspid                uint32
	auid                 uint32
	flags                uint32
	ktime                uint64
	cmdline              []byte
	exe                  []byte
	effective            uint64
	inheritable          uint64
	permitted            uint64
	uts_ns               uint32
	ipc_ns               uint32
	mnt_ns               uint32
	pid_ns               uint32
	pid_for_children_ns  uint32
	net_ns               uint32
	time_ns              uint32
	time_for_children_ns uint32
	cgroup_ns            uint32
	user_ns              uint32
	kernel_thread        bool
}

func procFilename(p *procs) string {
	filename := string(p.exe)

	// If this is a kernel thread, we use its filename as process name
	// similarly to what ps reports.
	if p.kernel_thread {
		return fmt.Sprintf("[%s]", filename)
	}

	return filename
}

func procArgs(p *procs) string {
	if p.kernel_thread {
		return ""
	}

	// skip argv[0], it's already resolved as the filename
	_, data, _ := bytes.Cut(p.cmdline, []byte{'\x00'})

	if len(data) > 0 && data[len(data)-1] == '\x00' {
		data = data[:len(data)-1]
	}

	if len(data) == 0 {
		return ""
	}

	var args strings.Builder

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

		if utf8.Valid(arg) {
			args.Write(arg)
		} else {
			args.WriteString(strutils.UTF8FromBPFBytes(arg))
		}

		if hasWhiteSpace {
			args.WriteByte('"')
		}
	}

	return args.String()
}

func procKernel() procs {
	kernelArgs := []byte("<kernel>")
	return procs{
		ppid:        kernelPid,
		pnspid:      0,
		pflags:      api.EventProcFS,
		pktime:      1,
		pid:         kernelPid,
		tid:         kernelPid,
		nspid:       0,
		auid:        0,
		flags:       api.EventProcFS,
		ktime:       1,
		exe:         kernelArgs,
		uids:        []uint32{0, 0, 0, 0},
		gids:        []uint32{0, 0, 0, 0},
		effective:   0,
		inheritable: 0,
		permitted:   0,
	}
}

func getCWD(pid uint32) (string, uint32) {
	flags := uint32(0)
	pidstr := fmt.Sprint(pid)

	if pid == 0 {
		return "", flags
	}

	cwd, err := os.Readlink(filepath.Join(option.Config.ProcFS, pidstr, "cwd"))
	if err != nil {
		flags |= api.EventRootCWD | api.EventErrorCWD
		return "", flags
	}

	return cwd, flags
}

func pushExecveEvents(p procs, inInitTreeMap map[uint32]struct{}) {
	var err error

	filename := procFilename(&p)
	args := procArgs(&p)
	cwd, flags := getCWD(p.pid)

	if p.kernel_thread {
		m := ossExec.MsgKThreadInitUnix{}
		m.Unix = &processapi.MsgExecveEventUnix{}

		m.Unix.Msg.Common = processapi.MsgCommon{}
		m.Unix.Msg.Kube = processapi.MsgK8s{}
		m.Unix.Msg.CleanupProcess = processapi.MsgExecveKey{}

		m.Unix.Msg.Parent.Pid = p.ppid
		m.Unix.Msg.Parent.Ktime = p.pktime

		m.Unix.Msg.Creds.Cap = processapi.MsgCapabilities{}
		m.Unix.Msg.Namespaces = processapi.MsgNamespaces{}

		m.Unix.Process.PID = p.pid
		m.Unix.Process.TID = p.pid
		m.Unix.Process.NSPID = p.nspid
		m.Unix.Process.UID = 0
		m.Unix.Process.AUID = proc.InvalidUid

		m.Unix.Process.Flags = api.EventProcFS
		m.Unix.Process.Ktime = p.ktime
		m.Unix.Process.Filename = filename
		m.Unix.Process.Args = ""

		observer.AllListeners(&m)
	} else {
		m := exec.MsgExecveEventUnix{}
		m.Unix = &processapi.MsgExecveEventUnix{}
		m.Unix.Msg.Common.Op = ops.MSG_OP_EXECVE

		m.Unix.Msg.Kube.Cgrpid = 0
		if p.pid > 0 {
			m.Unix.Kube.Docker, err = procsDockerId(p.pid)
			if err != nil {
				logger.GetLogger().Warn("Procfs execve event pods/ identifier error", logfields.Error, err)
			}
			if m.Unix.Kube.Docker != "" {
				if cgid, err := cgroups.CgroupIDFromPID(p.pid); err == nil {
					m.Unix.Msg.Kube.Cgrpid = cgid
					m.Unix.Kube.Cgrpid = cgid
				} else if option.Config.EnableCgIDmap {
					// only warn if cgidmap is enabled since this is where this
					// value is used
					logger.GetLogger().Warn("failed to find cgroup id for pid", logfields.Error, err, "pid", p.pid)
				}
			}
		}

		m.Unix.Msg.Parent.Pid = p.ppid
		m.Unix.Msg.Parent.Ktime = p.pktime

		caps := processapi.MsgCapabilities{
			Permitted:   p.permitted,
			Effective:   p.effective,
			Inheritable: p.inheritable,
		}

		m.Unix.Msg.Namespaces.UtsInum = p.uts_ns
		m.Unix.Msg.Namespaces.IpcInum = p.ipc_ns
		m.Unix.Msg.Namespaces.MntInum = p.mnt_ns
		m.Unix.Msg.Namespaces.PidInum = p.pid_ns
		m.Unix.Msg.Namespaces.PidChildInum = p.pid_for_children_ns
		m.Unix.Msg.Namespaces.NetInum = p.net_ns
		m.Unix.Msg.Namespaces.TimeInum = p.time_ns
		m.Unix.Msg.Namespaces.TimeChildInum = p.time_for_children_ns
		m.Unix.Msg.Namespaces.CgroupInum = p.cgroup_ns
		m.Unix.Msg.Namespaces.UserInum = p.user_ns

		m.Unix.Process.PID = p.pid
		m.Unix.Process.TID = p.tid
		m.Unix.Process.NSPID = p.nspid
		// use euid to be compatible with ps
		m.Unix.Process.UID = p.uids[1]
		m.Unix.Process.AUID = p.auid
		m.Unix.Msg.Creds = processapi.MsgGenericCred{
			Uid: p.uids[0], Euid: p.uids[1], Suid: p.uids[2], FSuid: p.uids[3],
			Gid: p.gids[0], Egid: p.gids[1], Sgid: p.gids[2], FSgid: p.gids[3],
			Cap: caps,
		}
		m.Unix.Process.Flags = p.flags | flags
		m.Unix.Process.Ktime = p.ktime
		m.Unix.Msg.Common.Ktime = p.ktime
		m.Unix.Process.Filename = filename
		m.Unix.Process.Args = args
		m.Unix.Process.Cwd = cwd

		if _, ok := inInitTreeMap[m.Unix.Process.PID]; ok {
			m.Unix.Process.Flags |= api.EventInInitTree
		}

		err := userinfo.MsgToExecveAccountUnix(m.Unix)
		if err != nil {
			logger.Trace(logger.GetLogger(), "Resolving process uid to username record failed", logfields.Error, err,
				"process.pid", p.pid, "process.binary", filename, "process.uid", m.Unix.Process.UID)
		}

		observer.AllListeners(&m)
	}
}

func updateExecveMapStats(procs int64) {
	execveMapStats := base.GetExecveMapStats()

	m, err := ebpf.LoadPinnedMap(filepath.Join(bpf.MapPrefixPath(), execveMapStats.Name), nil)
	if err != nil {
		logger.GetLogger().Error("Could not open execve_map_stats", logfields.Error, err)
		return
	}
	defer m.Close()

	if err := sensors.UpdateStatsMap(m, procs); err != nil {
		logger.GetLogger().Error("Failed to update execve_map_stats with procfs stats", logfields.Error, err)
	}
}

func procToKeyValue(p procs, inInitTree map[uint32]struct{}) (*execvemap.ExecveKey, *execvemap.ExecveValue) {
	k := &execvemap.ExecveKey{Pid: p.pid}
	v := &execvemap.ExecveValue{}

	v.Parent.Pid = p.ppid
	v.Parent.Ktime = p.pktime
	v.Process.Pid = p.pid
	v.Process.Ktime = p.ktime
	v.Flags = 0
	v.Nspid = p.nspid
	v.Capabilities.Permitted = p.permitted
	v.Capabilities.Effective = p.effective
	v.Capabilities.Inheritable = p.inheritable
	v.Namespaces.UtsInum = p.uts_ns
	v.Namespaces.IpcInum = p.ipc_ns
	v.Namespaces.MntInum = p.mnt_ns
	v.Namespaces.PidInum = p.pid_ns
	v.Namespaces.PidChildInum = p.pid_for_children_ns
	v.Namespaces.NetInum = p.net_ns
	v.Namespaces.TimeInum = p.time_ns
	v.Namespaces.TimeChildInum = p.time_for_children_ns
	v.Namespaces.CgroupInum = p.cgroup_ns
	v.Namespaces.UserInum = p.user_ns
	pathLength := copy(v.Binary.Path[:], p.exe)
	v.Binary.PathLength = int32(pathLength)

	_, parentInInitTree := inInitTree[p.ppid]
	if v.Nspid == 1 || parentInInitTree {
		v.Flags |= api.EventInInitTree
		inInitTree[p.pid] = struct{}{}
	}

	return k, v
}

func writeExecveMap(procs []procs) map[uint32]struct{} {
	mapDir := bpf.MapPrefixPath()

	execveMap := base.GetExecveMap()

	m, err := ebpf.LoadPinnedMap(filepath.Join(mapDir, execveMap.Name), nil)
	for i := 0; err != nil; i++ {
		m, err = ebpf.LoadPinnedMap(filepath.Join(mapDir, execveMap.Name), nil)
		if err != nil {
			time.Sleep(mapRetryDelay * time.Second)
		}
		if i > maxMapRetries {
			panic(err)
		}
	}
	inInitTree := make(map[uint32]struct{})
	for _, p := range procs {
		k, v := procToKeyValue(p, inInitTree)
		err := m.Put(k, v)
		if err != nil {
			logger.GetLogger().Warn("failed to put value in execve_map", logfields.Error, err, "value", v)
		}
	}
	// In order for kprobe events from kernel ctx to not abort we need the
	// execve lookup to map to a valid entry. So to simplify the kernel side
	// and avoid having to add another branch of logic there to handle pid==0
	// case we simply add it here.
	m.Put(&execvemap.ExecveKey{Pid: kernelPid}, &execvemap.ExecveValue{
		Parent: processapi.MsgExecveKey{
			Pid:   kernelPid,
			Ktime: 1},
		Process: processapi.MsgExecveKey{
			Pid:   kernelPid,
			Ktime: 1,
		},
	})
	m.Close()

	updateExecveMapStats(int64(len(procs)))

	return inInitTree
}

func pushEvents(ps []procs) {
	inInitTreeMap := writeExecveMap(ps)

	sort.Slice(ps, func(i, j int) bool {
		return ps[i].ppid < ps[j].ppid
	})
	ps = append([]procs{procKernel()}, ps...)
	for _, p := range ps {
		pushExecveEvents(p, inInitTreeMap)
	}
}

func listRunningProcs(procPath string) ([]procs, error) {
	var processes []procs

	procFS, err := os.ReadDir(procPath)
	if err != nil {
		return nil, err
	}

	for _, d := range procFS {
		var pstats []string
		var pktime uint64
		var pnspid uint32

		if !d.IsDir() {
			continue
		}

		pathName := filepath.Join(procPath, d.Name())

		// All processes have a directory name that consists from a number.
		if !regexp.MustCompile(`\d`).MatchString(d.Name()) {
			continue
		}

		cmdline, err := os.ReadFile(filepath.Join(pathName, "cmdline"))
		if err != nil {
			continue
		}

		// We read comm in the case where cmdling is empty (i.e. kernel thread).
		comm, err := os.ReadFile(filepath.Join(pathName, "comm"))
		if err != nil {
			continue
		}

		kernelThread := false
		if string(cmdline) == "" {
			cmdline = comm
			kernelThread = true
		}

		pid, err := proc.GetProcPid(d.Name())
		if err != nil {
			logger.GetLogger().Warn("pid read error", logfields.Error, err)
			continue
		}

		stats, err := proc.GetProcStatStrings(pathName)
		if err != nil {
			logger.GetLogger().Warn("stats read error", logfields.Error, err)
			continue
		}

		ppid := stats[3]
		_ppid, err := strconv.ParseUint(ppid, 10, 32)
		if err != nil {
			_ppid = 0 // 0 pid indicates no known parent
		}

		ktime, err := proc.GetStatsKtime(stats)
		if err != nil {
			logger.GetLogger().Warn("ktime read error", logfields.Error, err)
		}

		// Initialize with invalid uid
		uids := []uint32{proc.InvalidUid, proc.InvalidUid, proc.InvalidUid, proc.InvalidUid}
		gids := []uint32{proc.InvalidUid, proc.InvalidUid, proc.InvalidUid, proc.InvalidUid}
		auid := proc.InvalidUid
		// Get process status
		status, err := proc.GetStatus(pathName)
		if err != nil {
			logger.GetLogger().Warn("Reading process status error", logfields.Error, err)
		} else {
			uids, err = status.GetUids()
			if err != nil {
				logger.GetLogger().Warn(fmt.Sprintf("Reading Uids of %s failed, falling back to uid: %d", pathName, uint32(proc.InvalidUid)), logfields.Error, err)
			}

			gids, err = status.GetGids()
			if err != nil {
				logger.GetLogger().Warn(fmt.Sprintf("Reading Uids of %s failed, falling back to gid: %d", pathName, uint32(proc.InvalidUid)), logfields.Error, err)
			}

			auid, err = status.GetLoginUid()
			if err != nil {
				logger.GetLogger().Warn(fmt.Sprintf("Reading Loginuid of %s failed, falling back to loginuid: %d", pathName, uint32(auid)), logfields.Error, err)
			}
		}

		nspid, permitted, effective, inheritable := caps.GetPIDCaps(filepath.Join(procPath, d.Name(), "status"))

		uts_ns, err := namespace.GetPidNsInode(uint32(pid), "uts")
		if err != nil {
			logger.GetLogger().Warn("Reading uts namespace failed", logfields.Error, err)
		}
		ipc_ns, err := namespace.GetPidNsInode(uint32(pid), "ipc")
		if err != nil {
			logger.GetLogger().Warn("Reading ipc namespace failed", logfields.Error, err)
		}
		mnt_ns, err := namespace.GetPidNsInode(uint32(pid), "mnt")
		if err != nil {
			logger.GetLogger().Warn("Reading mnt namespace failed", logfields.Error, err)
		}
		pid_ns, err := namespace.GetPidNsInode(uint32(pid), "pid")
		if err != nil {
			logger.GetLogger().Warn("Reading pid namespace failed", logfields.Error, err)
		}
		pid_for_children_ns, err := namespace.GetPidNsInode(uint32(pid), "pid_for_children")
		if err != nil {
			logger.GetLogger().Warn("Reading pid_for_children namespace failed", logfields.Error, err)
		}
		net_ns, err := namespace.GetPidNsInode(uint32(pid), "net")
		if err != nil {
			logger.GetLogger().Warn("Reading net namespace failed", logfields.Error, err)
		}
		time_ns := uint32(0)
		time_for_children_ns := uint32(0)
		if namespace.TimeNsSupport {
			time_ns, err = namespace.GetPidNsInode(uint32(pid), "time")
			if err != nil {
				logger.GetLogger().Warn("Reading time namespace failed", logfields.Error, err)
			}
			time_for_children_ns, err = namespace.GetPidNsInode(uint32(pid), "time_for_children")
			if err != nil {
				logger.GetLogger().Warn("Reading time_for_children namespace failed", logfields.Error, err)
			}
		}
		cgroup_ns, err := namespace.GetPidNsInode(uint32(pid), "cgroup")
		if err != nil {
			logger.GetLogger().Warn("Reading cgroup namespace failed", logfields.Error, err)
		}
		user_ns, err := namespace.GetPidNsInode(uint32(pid), "user")
		if err != nil {
			logger.GetLogger().Warn("Reading user namespace failed", logfields.Error, err)
		}

		// On error procsDockerId zeros dockerId so we can ignore any errors.
		dockerId, _ := procsDockerId(uint32(pid))
		if dockerId == "" {
			// If we do not have a container ID, then set nspid to zero.
			// This field is used to construct the pod information to
			// identify pids inside the container.
			nspid = 0
		}

		if _ppid != 0 {
			var err error
			parentPath := filepath.Join(procPath, ppid)

			pstats, err = proc.GetProcStatStrings(string(parentPath))
			if err != nil {
				logger.GetLogger().Warn("parent stats read error", logfields.Error, err)
				continue
			}

			pktime, err = proc.GetStatsKtime(pstats)
			if err != nil {
				logger.GetLogger().Warn("parent ktime read error", logfields.Error, err)
			}

			if dockerId != "" {
				// We have a container ID so let's get the nspid inside.
				pnspid, _, _, _ = caps.GetPIDCaps(filepath.Join(procPath, ppid, "status"))
			}
		} else {
			pstats = nil
			pktime = 0
			pnspid = 0
		}

		execPath, err := os.Readlink(filepath.Join(procPath, d.Name(), "exe"))
		if err != nil {
			if kernelThread {
				execPath = strings.TrimSuffix(string(cmdline), "\n")
			} else {
				logger.GetLogger().Warn("reading process exe error", logfields.Error, err, "process", d.Name())
			}
		}

		p := procs{
			ppid:                 uint32(_ppid),
			pnspid:               pnspid,
			pflags:               api.EventProcFS | api.EventNeedsCWD,
			pktime:               pktime,
			uids:                 uids,
			gids:                 gids,
			auid:                 auid,
			pid:                  uint32(pid),
			tid:                  uint32(pid), // Read dir does not return threads and we only track tgid
			nspid:                nspid,
			exe:                  stringToUTF8([]byte(execPath)),
			cmdline:              stringToUTF8(cmdline),
			flags:                api.EventProcFS | api.EventNeedsCWD,
			ktime:                ktime,
			permitted:            permitted,
			effective:            effective,
			inheritable:          inheritable,
			uts_ns:               uts_ns,
			ipc_ns:               ipc_ns,
			mnt_ns:               mnt_ns,
			pid_ns:               pid_ns,
			pid_for_children_ns:  pid_for_children_ns,
			net_ns:               net_ns,
			time_ns:              time_ns,
			time_for_children_ns: time_for_children_ns,
			cgroup_ns:            cgroup_ns,
			user_ns:              user_ns,
			kernel_thread:        kernelThread,
		}

		processes = append(processes, p)
	}

	logger.GetLogger().Info(fmt.Sprintf("Read ProcFS %s appended %d/%d entries", option.Config.ProcFS, len(processes), len(procFS)))

	return processes, nil
}

func GetRunningProcs() error {
	procs, err := listRunningProcs(option.Config.ProcFS)
	if err != nil {
		logger.GetLogger().Error(fmt.Sprintf("Failed to list running processes from '%s'", option.Config.ProcFS), logfields.Error, err)
		return err
	}

	pushEvents(procs)
	return nil
}
