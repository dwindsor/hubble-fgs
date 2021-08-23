//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//
package observer

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/logger"
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

func (k *ObserverKprobe) _getTCPConnections(entryMap map[uint32]procTCPEntry, pid uint64, file string) error {
	pidStr := strconv.Itoa(int(pid))
	tcp, err := os.Open(filepath.Join(ProcFS, pidStr, file))
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
				k.log.Warn("ProcFS: /%s/%d/%s TCPConnections error: %s", ProcFS, pidStr, file, err)
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

func (k *ObserverKprobe) getTCPConnections(entryMap map[uint32]procTCPEntry, pid uint64) error {
	if err := k._getTCPConnections(entryMap, pid, "/net/tcp"); err != nil {
		return err
	}
	if err := k._getTCPConnections(entryMap, pid, "/net/tcp6"); err != nil {
		return err
	}
	return nil
}

func getClkTck() (uint64, error) {
	cmd := exec.Command("getconf", "CLK_TCK")
	out := new(bytes.Buffer)
	cmd.Stdout = out
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("command getconf failed: %w", err)
	}
	clktck, err := strconv.ParseUint(strings.TrimSpace(out.String()), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("command getconf parse failed: %w", err)
	}
	return clktck, nil
}

func getPIDNS(filename string) (uint32, uint64, uint64, uint64) {
	pid := uint32(0)
	permitted := uint64(0)
	effective := uint64(0)
	inheritable := uint64(0)

	getValue64Hex := func(line string) (uint64, error) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("Fields to few arguments")
		}
		pidField := fields[len(fields)-1]
		pid, err := strconv.ParseUint(pidField, 16, 64)
		return pid, err
	}

	getValue32Int := func(line string) (uint32, error) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("Fields to few arguments")
		}
		pidField := fields[len(fields)-1]
		pid, err := strconv.ParseUint(pidField, 10, 32)
		return uint32(pid), err
	}

	file, err := ioutil.ReadFile(filename)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("ReadFile failed: %s", filename)
		return 0, 0, 0, 0
	}
	statuslines := strings.Split(string(file), "\n")
	for _, line := range statuslines {
		err = nil
		if strings.Contains(line, "NStgid:") {
			pid, err = getValue32Int(line)
		}
		if strings.Contains(line, "CapPrm:") {
			permitted, err = getValue64Hex(line)
		}
		if strings.Contains(line, "CapEff:") {
			effective, err = getValue64Hex(line)
		}
		if strings.Contains(line, "CapInh:") {
			inheritable, err = getValue64Hex(line)
		}
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("ReadFile (%s) error: %s", line, filename)
		}
	}
	return pid, permitted, effective, inheritable
}

type ObserverProcs struct {
	psize       uint32
	puid        uint32
	ppid        uint32
	pnspid      uint32
	pauid       uint32
	pflags      uint32
	pktime      uint64
	pargs       []byte
	size        uint32
	uid         uint32
	pid         uint32
	nspid       uint32
	auid        uint32
	flags       uint32
	ktime       uint64
	args        []byte
	effective   uint64
	inheritable uint64
	permitted   uint64
}

func (k *ObserverKprobe) pushEvents(procs []ObserverProcs, tcpEntries map[uint32]procTCPEntry, pushExecve, writeMaps bool) {
	if writeMaps {
		k.writeExecveMap(procs)
	}
	sort.Slice(procs, func(i, j int) bool {
		return procs[i].ppid < procs[j].ppid
	})
	for _, p := range procs {
		k.pushExecveEvents(p, tcpEntries, pushExecve, writeMaps)
	}
	// Ensure we have at least a default dockerId offset if we failed
	// to disover one while walking proc
	err := procDockerIdOffsetDefault(btf.GetCachedBTF())
	if err != nil {
		k.log.Warn("prodDockerIdOffsetDefault error: %s", err)
	}
}

func (k *ObserverKprobe) getRunningProcs(write, push bool) []ObserverProcs {
	var entryMap = make(map[uint32]procTCPEntry)
	var procs []ObserverProcs
	procFS, _ := ioutil.ReadDir(ProcFS)
	r := regexp.MustCompile(`[^\s\(]+|(\({1,2}[^\)]*\){1,2})`)

	clktck, err := getClkTck()
	if err != nil {
		k.log.WithError(err).Warn("procFS wallclock time may be inaccurate")
		clktck = 1
	}

	for _, d := range procFS {
		var pcmdline, pstatline []byte
		var pstats []string
		var pktime uint64
		var pexecPath string
		var pnspid uint32

		if d.IsDir() == false {
			continue
		}
		cmdline, err := ioutil.ReadFile(filepath.Join(ProcFS, d.Name(), "cmdline"))
		if err != nil {
			continue
		}
		if string(cmdline) == "" {
			continue
		}
		statline, err := ioutil.ReadFile(filepath.Join(ProcFS, d.Name(), "stat"))
		if err != nil {
			k.log.WithError(err).Warnf("ReadFile: %s /stat error", filepath.Join(ProcFS, d.Name(), "cmdline"))
			continue
		}
		pid, err := strconv.ParseUint(d.Name(), 10, 32)
		if err != nil {
			k.log.WithError(err).Warnf("ReadFile: %s /parseuint error", filepath.Join(ProcFS, d.Name(), "cmdline"))
			continue
		}

		stats := r.FindAllString(string(statline), -1)
		ppid := stats[3]
		_ppid, err := strconv.ParseUint(ppid, 10, 32)
		if err != nil {
			_ppid = 0 // 0 pid indicates no known parent
		}

		_ktime := stats[21]
		ktime, err := strconv.ParseUint(_ktime, 10, 64)
		if err != nil {
			k.log.WithError(err).Warnf("Ktime parsing error: %s: %s", _ktime, filepath.Join(ProcFS, ppid, "stat"))
			ktime = 0
		}
		ktime = ktime * (nanoPerSeconds / clktck)
		nspid, permitted, effective, inheritable := getPIDNS(filepath.Join(ProcFS, d.Name(), "status"))

		// On error procsDockerId zeros dockerId so we can ignore any errors.
		dockerId, _, _ := procsDockerId(uint32(pid))
		if dockerId == "" {
			nspid = 0
		}

		if _ppid != 0 {
			var err error

			pcmdline, err = ioutil.ReadFile(filepath.Join(ProcFS, ppid, "cmdline"))
			if err != nil {
				k.log.WithError(err).Warnf("ReadFile: %s /cmdline error", filepath.Join(ProcFS, d.Name(), "cmdline"))
				continue
			}

			pstatline, err = ioutil.ReadFile(filepath.Join(ProcFS, ppid, "stat"))
			if err != nil {
				k.log.WithError(err).Warnf("ReadFile: %s /stat error", filepath.Join(ProcFS, d.Name(), "cmdline"))
				continue
			}
			pstats = r.FindAllString(string(pstatline), -1)
			_pktime := pstats[21]
			pktime, err = strconv.ParseUint(_pktime, 10, 64)
			if err != nil {
				k.log.WithError(err).Warnf("Warning: Parent ktime parsing error: %s: %s", _pktime, filepath.Join(ProcFS, ppid, "stat"))
				pktime = 0
			}
			pktime = pktime * (nanoPerSeconds / clktck)
			if dockerId != "" {
				pnspid, _, _, _ = getPIDNS(filepath.Join(ProcFS, ppid, "status"))
			}
		} else {
			pcmdline = nil
			pstatline = nil
			pstats = nil
			pktime = 0
			pnspid = 0
		}

		execPath, err := os.Readlink(filepath.Join(ProcFS, d.Name(), "exe"))
		if err == nil {
			cmdline = prependPath(execPath, cmdline)
		}

		if _ppid != 0 {
			pexecPath, err = os.Readlink(filepath.Join(ProcFS, ppid, "exe"))
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
			flags:       api.EventProcFS | api.EventNeedsCWD | api.EventNeedsAUID,
			ktime:       ktime,
			permitted:   permitted,
			effective:   effective,
			inheritable: inheritable,
		}

		p.size = uint32(api.SIZEOF_EXECVE + len(p.args) + api.MAX_SIZEOF_CWD)
		p.psize = uint32(api.SIZEOF_EXECVE + len(p.pargs) + api.MAX_SIZEOF_CWD)
		/* If we can't fit this in the buffer lets trim some parts and
		 * make it fit.
		 */
		if p.size+p.psize > api.ARGSBUFFER {
			var deduct uint32
			var need int32

			need = int32((p.size + p.psize) - api.ARGSBUFFER)
			// First consume CWD space from parent because this speculative extra space
			// next try to consume CWD space from child and finally start truncating args
			// if necessary.
			deduct = api.MAX_SIZEOF_CWD
			p.pflags = p.pflags & ^uint32(api.EventNeedsCWD)
			p.pflags = p.pflags | api.EventNoCWDSupport
			p.psize -= deduct
			need -= int32(deduct)
			if need > 0 {
				deduct = api.MAX_SIZEOF_CWD
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
	k.log.Infof("Read ProcFS %s appended %d/%d entries", ProcFS, len(procs), len(procFS))

	k.pushEvents(procs, entryMap, push, write)
	return procs
}
