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
	"bufio"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/reader/proc"
)

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

func _getTCPConnections(entryMap map[uint32]procTCPEntry, pid uint64, file string) error {
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
				logger.GetLogger().Warn("ProcFS: /%s/%d/%s TCPConnections error: %s", option.Config.ProcFS, pidStr, file, err)
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

func getTCPConnections(entryMap map[uint32]procTCPEntry, pid uint64, supportTCP6 bool) error {
	if err := _getTCPConnections(entryMap, pid, "/net/tcp"); err != nil {
		return err
	}
	if err := _getTCPConnections(entryMap, pid, "/net/tcp6"); err != nil {
		return err
	}
	return nil
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

func getRunningSockets(writeMaps, pushEvents bool) {
	var entryMap = make(map[uint32]procTCPEntry)
	hasSupportTCP6 := supportTCP6()

	procFS, err := ioutil.ReadDir(option.Config.ProcFS)
	if err != nil {
		logger.GetLogger().WithError(err).Error("GetRunningSockets ProcFS readdir error.")
		return
	}

	for _, d := range procFS {
		pathName := filepath.Join(option.Config.ProcFS, d.Name())

		pid, err := proc.GetProcPid(d.Name())
		if err != nil {
			continue
		}

		stats, err := proc.GetProcStatStrings(pathName)
		if err != nil {
			continue
		}

		ktime, err := proc.GetStatsKtime(stats)
		if err != nil {
			continue
		}

		if err := getTCPConnections(entryMap, pid, hasSupportTCP6); err != nil {
			logger.GetLogger().WithError(err).Warn("Failed to parse and build proc net map. Will not post connections started before hubble-fgs.")
		}
		pushTCPEvents(uint32(pid), ktime, entryMap, writeMaps, pushEvents)
	}

}
