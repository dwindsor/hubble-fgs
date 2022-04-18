//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package observer

import (
	"bufio"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/reader"
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

func stringToTCPEntry(s string) (*procTCPEntry, error) {
	var entry procTCPEntry

	fields := strings.Fields(s)

	id, _ := strconv.ParseUint(strings.TrimRight(fields[0], ":"), 10, 32)
	local := strings.Split(fields[1], ":")
	remote := strings.Split(fields[2], ":")
	localIP, err := strconv.ParseUint(local[0], 16, 32)
	if err != nil {
		return nil, err
	}
	localPort, err := strconv.ParseUint(local[1], 16, 16)
	if err != nil {
		return nil, err
	}
	remoteIP, err := strconv.ParseUint(remote[0], 16, 32)
	if err != nil {
		return nil, err
	}
	remotePort, err := strconv.ParseUint(remote[1], 16, 16)
	if err != nil {
		return nil, err
	}
	state, err := strconv.ParseUint(fields[3], 16, 32)
	if err != nil {
		return nil, err
	}
	inode, err := strconv.ParseUint(fields[9], 10, 32)
	if err != nil {
		return nil, err
	}

	entry.id = int(id)
	entry.inode = uint32(inode)
	entry.localIP = uint32(localIP)
	entry.localPort = uint16(localPort)
	entry.remoteIP = uint32(remoteIP)
	entry.remotePort = uint16(remotePort)
	entry.state = uint32(state)

	return &entry, nil
}

// supportTCP6 returns whether or not the kernel has support for /proc/<pid>/net/tcp6
// entries. We do this by testing for the existence of /proc/net/tcp6.
func supportTCP6() bool {
	if _, err := os.Stat("/proc/net/tcp6"); err == nil {
		logger.GetLogger().Infof("ProcFS: Detected TCP6 support")
		return true
	}
	logger.GetLogger().Infof("ProcFS: Detected no TCP6 support")
	return false
}

func (k *Observer) _getTCPConnections(entryMap map[uint32]procTCPEntry, pid uint64, file string) error {
	pidStr := strconv.Itoa(int(pid))
	tcp, err := os.Open(filepath.Join(option.Config.ProcFS, pidStr, file))
	if err != nil {
		return err
	}
	defer tcp.Close()
	scanner := bufio.NewScanner(tcp)
	scanner.Scan()
	for scanner.Scan() {
		entry, err := stringToTCPEntry(scanner.Text())
		// We do not handle IPv6 yet so we may get expected errors
		// in these cases. When this happens just continue otherwise
		// lets ensure we log it.
		if err != nil {
			if file != "/net/tcp6" {
				k.log.Warn("ProcFS: /%s/%d/%s TCPConnections error: %s", option.Config.ProcFS, pidStr, file, err)
			}
			continue
		}
		entryMap[entry.inode] = *entry
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func (k *Observer) getTCPConnections(entryMap map[uint32]procTCPEntry, pid uint64, supportTCP6 bool) error {
	if err := k._getTCPConnections(entryMap, pid, "/net/tcp"); err != nil {
		return err
	}
	if supportTCP6 {
		if err := k._getTCPConnections(entryMap, pid, "/net/tcp6"); err != nil {
			return err
		}
	}
	return nil
}

type Procs struct {
	psize                uint32
	ppid                 uint32
	pnspid               uint32
	pflags               uint32
	pktime               uint64
	pargs                []byte
	size                 uint32
	uid                  uint32
	pid                  uint32
	nspid                uint32
	auid                 uint32
	flags                uint32
	ktime                uint64
	args                 []byte
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
}

func (k *Observer) pushEvents(procs []Procs, pushExecve, writeMaps bool) {
	if writeMaps {
		k.writeExecveMap(procs)
	}
	sort.Slice(procs, func(i, j int) bool {
		return procs[i].ppid < procs[j].ppid
	})
	procs = append(procs, k.procKernel())
	for _, p := range procs {
		k.pushExecveEvents(p, pushExecve, writeMaps)
	}
	// Ensure we have at least a default dockerId offset if we failed
	// to discover one while walking proc
	err := procDockerIdOffsetDefault(btf.GetCachedBTF())
	if err != nil {
		k.log.Warn("prodDockerIdOffsetDefault error: %s", err)
	}
}

func (k *Observer) getRunningProcs(write, push bool) []Procs {
	var procs []Procs
	procFS, err := ioutil.ReadDir(option.Config.ProcFS)
	if err != nil {
		k.log.WithError(err).Errorf("Could not read directory %s", option.Config.ProcFS)
		return nil
	}

	kernelVer, _, _ := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	// time and time_for_children namespaces introduced in kernel 5.6
	hasTimeNs := (int64(kernelVer) >= kernels.KernelStringToNumeric("5.6.0"))

	for _, d := range procFS {
		var pcmdline []byte
		var pstats []string
		var pktime uint64
		var pexecPath string
		var pnspid uint32

		if d.IsDir() == false {
			continue
		}

		pathName := filepath.Join(option.Config.ProcFS, d.Name())

		cmdline, err := ioutil.ReadFile(filepath.Join(pathName, "cmdline"))
		if err != nil {
			continue
		}
		if string(cmdline) == "" {
			continue
		}

		pid, err := reader.GetProcPid(d.Name())
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("pid read error")
			continue
		}

		stats, err := reader.GetProcStatStrings(pathName)
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("stats read error")
			continue
		}

		ppid := stats[3]
		_ppid, err := strconv.ParseUint(ppid, 10, 32)
		if err != nil {
			_ppid = 0 // 0 pid indicates no known parent
		}

		ktime, err := reader.GetStatsKtime(stats)
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("ktime read error")
		}

		nspid, permitted, effective, inheritable := reader.GetPIDCaps(filepath.Join(option.Config.ProcFS, d.Name(), "status"))

		uts_ns := reader.GetPidNsInode(uint32(pid), "uts")
		ipc_ns := reader.GetPidNsInode(uint32(pid), "ipc")
		mnt_ns := reader.GetPidNsInode(uint32(pid), "mnt")
		pid_ns := reader.GetPidNsInode(uint32(pid), "pid")
		pid_for_children_ns := reader.GetPidNsInode(uint32(pid), "pid_for_children")
		net_ns := reader.GetPidNsInode(uint32(pid), "net")
		time_ns := uint32(0)
		time_for_children_ns := uint32(0)
		if hasTimeNs {
			time_ns = reader.GetPidNsInode(uint32(pid), "time")
			time_for_children_ns = reader.GetPidNsInode(uint32(pid), "time_for_children")
		}
		cgroup_ns := reader.GetPidNsInode(uint32(pid), "cgroup")
		user_ns := reader.GetPidNsInode(uint32(pid), "user")

		// On error procsDockerId zeros dockerId so we can ignore any errors.
		dockerId, _, _ := procsDockerId(uint32(pid))
		if dockerId == "" {
			nspid = 0
		}

		if _ppid != 0 {
			var err error
			parentPath := filepath.Join(option.Config.ProcFS, ppid)

			pcmdline, err = ioutil.ReadFile(filepath.Join(parentPath, "cmdline"))
			if err != nil {
				logger.GetLogger().WithError(err).WithField("path", parentPath).Warn("parent cmdline error")
				continue
			}

			pstats, err = reader.GetProcStatStrings(string(parentPath))
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("parent stats read error")
				continue
			}

			pktime, err = reader.GetStatsKtime(pstats)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("parent ktime read error")
			}

			if dockerId != "" {
				pnspid, _, _, _ = reader.GetPIDCaps(filepath.Join(option.Config.ProcFS, ppid, "status"))
			}
		} else {
			pcmdline = nil
			pstats = nil
			pktime = 0
			pnspid = 0
		}

		execPath, err := os.Readlink(filepath.Join(option.Config.ProcFS, d.Name(), "exe"))
		if err == nil {
			cmdline = prependPath(execPath, cmdline)
		}

		if _ppid != 0 {
			pexecPath, err = os.Readlink(filepath.Join(option.Config.ProcFS, ppid, "exe"))
			if err == nil {
				pcmdline = prependPath(pexecPath, pcmdline)
			}
		} else {
			pexecPath = ""
		}

		pcmdsUTF := stringToUTF8(pcmdline)
		cmdsUTF := stringToUTF8(cmdline)

		p := Procs{
			ppid: uint32(_ppid), pnspid: pnspid, pargs: pcmdsUTF,
			pflags: api.EventProcFS | api.EventNeedsCWD | api.EventNeedsAUID,
			pktime: pktime,
			pid:    uint32(pid), nspid: nspid, args: cmdsUTF,
			flags:                api.EventProcFS | api.EventNeedsCWD | api.EventNeedsAUID,
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
		}

		p.size = uint32(api.MSG_SIZEOF_EXECVE + len(p.args) + api.MSG_SIZEOF_CWD)
		p.psize = uint32(api.MSG_SIZEOF_EXECVE + len(p.pargs) + api.MSG_SIZEOF_CWD)
		/* If we can't fit this in the buffer lets trim some parts and
		 * make it fit.
		 */
		if p.size+p.psize > api.MSG_SIZEOF_BUFFER {
			var deduct uint32
			var need int32

			need = int32((p.size + p.psize) - api.MSG_SIZEOF_BUFFER)
			// First consume CWD space from parent because this speculative extra space
			// next try to consume CWD space from child and finally start truncating args
			// if necessary.
			deduct = api.MSG_SIZEOF_CWD
			p.pflags = p.pflags & ^uint32(api.EventNeedsCWD)
			p.pflags = p.pflags | api.EventNoCWDSupport
			p.psize -= deduct
			need -= int32(deduct)
			if need > 0 {
				deduct = api.MSG_SIZEOF_CWD
				p.size -= deduct
				p.flags = p.flags & ^uint32(api.EventNeedsCWD)
				p.flags = p.flags | api.EventNoCWDSupport
				need -= int32(deduct)
			}

			for i := int32(0); i < need; i++ {
				if len(p.pargs) > len(p.args) {
					p.pflags |= api.EventTruncArgs
					p.pargs = p.pargs[:len(p.pargs)-1]
					p.psize--
				} else {
					p.flags |= api.EventTruncArgs
					p.args = p.args[:len(p.args)-1]
					p.size--
				}
			}
		}

		procs = append(procs, p)
	}
	k.log.Infof("Read ProcFS %s appended %d/%d entries", option.Config.ProcFS, len(procs), len(procFS))

	k.pushEvents(procs, push, write)
	return procs
}

func (k *Observer) getRunningSockets(procs []Procs, writeMaps, pushEvents bool) {
	var entryMap = make(map[uint32]procTCPEntry)
	// Check for TCP6 support in procfs
	hasSupportTCP6 := supportTCP6()

	procFS, err := ioutil.ReadDir(option.Config.ProcFS)
	if err != nil {
		logger.GetLogger().WithError(err).Error("GetRunningSockets ProcFS readdir error.")
		return
	}

	for _, d := range procFS {
		pathName := filepath.Join(option.Config.ProcFS, d.Name())

		pid, err := reader.GetProcPid(d.Name())
		if err != nil {
			continue
		}

		stats, err := reader.GetProcStatStrings(pathName)
		if err != nil {
			continue
		}

		ktime, err := reader.GetStatsKtime(stats)
		if err != nil {
			continue
		}

		if err := k.getTCPConnections(entryMap, pid, hasSupportTCP6); err != nil {
			k.log.WithError(err).Warn("Failed to parse and build proc net map. Will not post connections started before hubble-fgs.")
		}
		k.pushTCPEvents(uint32(pid), ktime, entryMap, writeMaps, pushEvents)
	}

}
