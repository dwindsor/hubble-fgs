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
	"github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/reader"
)

func stringToUTF8(s []byte) []byte {
	var utf8Cursor int = 0
	var i int = 0

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

func (k *Observer) getTCPConnections(entryMap map[uint32]procTCPEntry, pid uint64) error {
	if err := k._getTCPConnections(entryMap, pid, "/net/tcp"); err != nil {
		return err
	}
	if err := k._getTCPConnections(entryMap, pid, "/net/tcp6"); err != nil {
		return err
	}
	return nil
}

type ObserverProcs struct {
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

func (k *Observer) pushEvents(procs []ObserverProcs, tcpEntries map[uint32]procTCPEntry, pushExecve, writeMaps bool) {
	if writeMaps {
		k.writeExecveMap(procs)
	}
	sort.Slice(procs, func(i, j int) bool {
		return procs[i].ppid < procs[j].ppid
	})
	procs = append(procs, k.procKernel())
	for _, p := range procs {
		k.pushExecveEvents(p, tcpEntries, pushExecve, writeMaps)
	}
	// Ensure we have at least a default dockerId offset if we failed
	// to discover one while walking proc
	err := procDockerIdOffsetDefault(btf.GetCachedBTF())
	if err != nil {
		k.log.Warn("prodDockerIdOffsetDefault error: %s", err)
	}
}

// The /proc/PID/stat file consists of a single line of space-separated strings, where
// the 2nd string contains the process' comm. This string is wrapped in brackets but can
// contain spaces and brackets. The correct way to parse this stat string is to find all
// space-separated strings working backwards from the end until a string is found that
// ends in a space, then find the first string and everything left must be the comm.
func getProcStatStrings(procStat string) []string {
	var output []string

	// Build list of strings in reverse order
	oldIndex := len(procStat)
	index := strings.LastIndexByte(procStat, ' ')
	for index > 0 {
		output = append(output, procStat[index+1:oldIndex])
		if procStat[index-1] == ')' {
			break
		}
		oldIndex = index
		index = strings.LastIndexByte(procStat[:oldIndex], ' ')
	}

	if index == -1 {
		// Did not hit ')'
		output = append(output, procStat[:oldIndex])
	} else {
		// Find the comm and first field
		commIndex := strings.IndexByte(procStat, ' ')
		output = append(output, procStat[commIndex+1:index])
		output = append(output, procStat[:commIndex])
	}

	// Reverse the array
	for i, j := 0, len(output)-1; i < j; i, j = i+1, j-1 {
		output[i], output[j] = output[j], output[i]
	}

	return output
}

func (k *Observer) getRunningProcs(write, push bool) []ObserverProcs {
	var entryMap = make(map[uint32]procTCPEntry)
	var procs []ObserverProcs
	procFS, err := ioutil.ReadDir(option.Config.ProcFS)
	if err != nil {
		k.log.WithError(err).Errorf("Could not read directory %s", option.Config.ProcFS)
		return nil
	}

	kernelVer, _, _ := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	// time and time_for_children namespaces introduced in kernel 5.6
	hasTimeNs := (int64(kernelVer) >= kernels.KernelStringToNumeric("5.6.0"))

	// CLK_TCK is always constant 100 on all architectures except alpha and ia64 which are both
	// obsolete and not supported by FGS. Also see
	// https://lore.kernel.org/lkml/agtlq6$iht$1@penguin.transmeta.com/ and
	// https://github.com/containerd/cgroups/pull/12
	clktck := uint64(100)

	for _, d := range procFS {
		var pcmdline, pstatline []byte
		var pstats []string
		var pktime uint64
		var pexecPath string
		var pnspid uint32

		if d.IsDir() == false {
			continue
		}
		cmdline, err := ioutil.ReadFile(filepath.Join(option.Config.ProcFS, d.Name(), "cmdline"))
		if err != nil {
			continue
		}
		if string(cmdline) == "" {
			continue
		}
		statline, err := ioutil.ReadFile(filepath.Join(option.Config.ProcFS, d.Name(), "stat"))
		if err != nil {
			k.log.WithError(err).Warnf("ReadFile: %s /stat error", filepath.Join(option.Config.ProcFS, d.Name(), "cmdline"))
			continue
		}
		pid, err := strconv.ParseUint(d.Name(), 10, 32)
		if err != nil {
			k.log.WithError(err).Warnf("ReadFile: %s /parseuint error", filepath.Join(option.Config.ProcFS, d.Name(), "cmdline"))
			continue
		}

		stats := getProcStatStrings(string(statline))
		ppid := stats[3]
		_ppid, err := strconv.ParseUint(ppid, 10, 32)
		if err != nil {
			_ppid = 0 // 0 pid indicates no known parent
		}

		_ktime := stats[21]
		ktime, err := strconv.ParseUint(_ktime, 10, 64)
		if err != nil {
			k.log.WithError(err).Warnf("Ktime parsing error: %s: %s", _ktime, filepath.Join(option.Config.ProcFS, ppid, "stat"))
			ktime = 0
		}
		ktime = ktime * (nanoPerSeconds / clktck)
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

			pcmdline, err = ioutil.ReadFile(filepath.Join(option.Config.ProcFS, ppid, "cmdline"))
			if err != nil {
				k.log.WithError(err).Warnf("ReadFile: %s /cmdline error", filepath.Join(option.Config.ProcFS, d.Name(), "cmdline"))
				continue
			}

			pstatline, err = ioutil.ReadFile(filepath.Join(option.Config.ProcFS, ppid, "stat"))
			if err != nil {
				k.log.WithError(err).Warnf("ReadFile: %s /stat error", filepath.Join(option.Config.ProcFS, d.Name(), "cmdline"))
				continue
			}
			pstats = getProcStatStrings(string(pstatline))
			_pktime := pstats[21]
			pktime, err = strconv.ParseUint(_pktime, 10, 64)
			if err != nil {
				k.log.WithError(err).Warnf("Warning: Parent ktime parsing error: %s: %s", _pktime, filepath.Join(option.Config.ProcFS, ppid, "stat"))
				pktime = 0
			}
			pktime = pktime * (nanoPerSeconds / clktck)
			if dockerId != "" {
				pnspid, _, _, _ = reader.GetPIDCaps(filepath.Join(option.Config.ProcFS, ppid, "status"))
			}
		} else {
			pcmdline = nil
			pstatline = nil
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

		p := ObserverProcs{
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

		// Collect any TCP connections associated with this pid
		if err = k.getTCPConnections(entryMap, pid); err != nil {
			k.log.WithError(err).Warn("Failed to parse and build proc net map. Will not post connections started before hubble-fgs.")
		}
	}
	k.log.Infof("Read ProcFS %s appended %d/%d entries", option.Config.ProcFS, len(procs), len(procFS))

	k.pushEvents(procs, entryMap, push, write)
	return procs
}
