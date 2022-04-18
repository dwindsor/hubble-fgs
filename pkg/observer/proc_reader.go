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
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
	procs = append(procs, procKernel())
	for _, p := range procs {
		k.pushExecveEvents(p, pushExecve, writeMaps)
	}
	// Ensure we have at least a default dockerId offset if we failed
	// to discover one while walking proc
	err := procDockerIdOffsetDefault(btf.GetCachedBTF())
	if err != nil {
		logger.GetLogger().Warn("prodDockerIdOffsetDefault error: %s", err)
	}
}

func (k *Observer) getRunningProcs(write, push bool) []Procs {
	var procs []Procs

	procFS, err := ioutil.ReadDir(option.Config.ProcFS)
	if err != nil {
		logger.GetLogger().WithError(err).Errorf("Could not read directory %s", option.Config.ProcFS)
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
	logger.GetLogger().Infof("Read ProcFS %s appended %d/%d entries", option.Config.ProcFS, len(procs), len(procFS))

	k.pushEvents(procs, push, write)
	return procs
}
