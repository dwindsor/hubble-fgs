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

package reader

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/option"
)

func GetPidNsInode(pid uint32, nsStr string) uint32 {
	pidStr := strconv.Itoa(int(pid))
	netns := filepath.Join(option.Config.ProcFS, pidStr, "ns", nsStr)
	netStr, err := os.Readlink(netns)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("GetPidNsInode")
		return 0
	}
	fields := strings.Split(netStr, ":")
	if len(fields) < 2 {
		logger.GetLogger().Errorf("GetPidNsInode: Error cannot parse %s\n", netStr)
		return 0
	}
	inode := fields[1]
	inode = strings.TrimRight(inode, "]")
	inode = strings.TrimLeft(inode, "[")
	inodeEntry, _ := strconv.ParseUint(inode, 10, 32)
	return uint32(inodeEntry)
}

func GetMyPidG() uint32 {
	selfBinary := filepath.Base(os.Args[0])
	if procfs := os.Getenv("FGS_PROCFS"); procfs != "" {
		procFS, _ := ioutil.ReadDir(procfs)
		for _, d := range procFS {
			if d.IsDir() == false {
				continue
			}
			cmdline, err := ioutil.ReadFile(filepath.Join(procfs, d.Name(), "/cmdline"))
			if err != nil {
				continue
			}
			if strings.Contains(string(cmdline), selfBinary) {
				pid, err := strconv.ParseUint(d.Name(), 10, 32)
				if err != nil {
					continue
				}
				return uint32(pid)
			}
		}
	}
	return uint32(os.Getpid())
}

func GetHostNsInode(nsStr string) uint32 {
	return GetPidNsInode(1, nsStr)
}

func GetSelfNsInode(nsStr string) uint32 {
	return GetPidNsInode(uint32(GetMyPidG()), nsStr)
}

func GetCurrentNamespace() *fgs.Namespaces {
	nses := [10]string{"uts", "ipc", "mnt", "pid", "pid_for_children", "net", "time", "time_for_children", "cgroup", "user"}
	self_ns := make(map[string]uint32)
	is_root_ns := make(map[string]bool)
	for i := 0; i < len(nses); i++ {
		self_ns[nses[i]] = GetSelfNsInode(nses[i])
		is_root_ns[nses[i]] = (self_ns[nses[i]] == GetHostNsInode(nses[i]))
	}

	return &fgs.Namespaces{
		Uts: &fgs.Namespace{
			Inum:   self_ns["uts"],
			IsHost: is_root_ns["uts"],
		},
		Ipc: &fgs.Namespace{
			Inum:   self_ns["ipc"],
			IsHost: is_root_ns["ipc"],
		},
		Mnt: &fgs.Namespace{
			Inum:   self_ns["mnt"],
			IsHost: is_root_ns["mnt"],
		},
		Pid: &fgs.Namespace{
			Inum:   self_ns["pid"],
			IsHost: is_root_ns["pid"],
		},
		PidForChildren: &fgs.Namespace{
			Inum:   self_ns["pid_for_children"],
			IsHost: is_root_ns["pid_for_children"],
		},
		Net: &fgs.Namespace{
			Inum:   self_ns["net"],
			IsHost: is_root_ns["net"],
		},
		Time: &fgs.Namespace{
			Inum:   self_ns["time"],
			IsHost: is_root_ns["time"],
		},
		TimeForChildren: &fgs.Namespace{
			Inum:   self_ns["time_for_children"],
			IsHost: is_root_ns["time_for_children"],
		},
		Cgroup: &fgs.Namespace{
			Inum:   self_ns["cgroup"],
			IsHost: is_root_ns["cgroup"],
		},
		User: &fgs.Namespace{
			Inum:   self_ns["user"],
			IsHost: is_root_ns["user"],
		},
	}
}
