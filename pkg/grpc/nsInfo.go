package grpc

import (
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	fgsAPI "github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/reader"
)

func createHostNs(ns string) *fgs.Namespace {
	return &fgs.Namespace{
		Inum:   reader.GetPidNsInode(1, ns),
		IsHost: true,
	}
}

func getHostNamespace() *fgs.Namespaces {
	if hostNamespace == nil {
		hostNamespace = &fgs.Namespaces{
			Uts:             createHostNs("uts"),
			Ipc:             createHostNs("ipc"),
			Mnt:             createHostNs("mnt"),
			Pid:             createHostNs("pid"),
			PidForChildren:  createHostNs("pid_for_children"),
			Net:             createHostNs("net"),
			Time:            createHostNs("time"),
			TimeForChildren: createHostNs("time_for_children"),
			Cgroup:          createHostNs("cgroup"),
			User:            createHostNs("user"),
		}
	}
	return hostNamespace
}

func (pm *ProcessManager) getNamespaces(ns fgsAPI.MsgNamespaces) *fgs.Namespaces {
	hostNs := getHostNamespace()
	retVal := &fgs.Namespaces{
		Uts: &fgs.Namespace{
			Inum:   ns.UtsInum,
			IsHost: hostNs.Uts.Inum == ns.UtsInum,
		},
		Ipc: &fgs.Namespace{
			Inum:   ns.IpcInum,
			IsHost: hostNs.Ipc.Inum == ns.IpcInum,
		},
		Mnt: &fgs.Namespace{
			Inum:   ns.MntInum,
			IsHost: hostNs.Mnt.Inum == ns.MntInum,
		},
		Pid: &fgs.Namespace{
			Inum:   ns.PidInum,
			IsHost: hostNs.Pid.Inum == ns.PidInum,
		},
		PidForChildren: &fgs.Namespace{
			Inum:   ns.PidChildInum,
			IsHost: hostNs.PidForChildren.Inum == ns.PidChildInum,
		},
		Net: &fgs.Namespace{
			Inum:   ns.NetInum,
			IsHost: hostNs.Net.Inum == ns.NetInum,
		},
		Time: &fgs.Namespace{
			Inum:   ns.TimeInum,
			IsHost: hostNs.Time.Inum == ns.TimeInum,
		},
		TimeForChildren: &fgs.Namespace{
			Inum:   ns.TimeChildInum,
			IsHost: hostNs.TimeForChildren.Inum == ns.TimeChildInum,
		},
		Cgroup: &fgs.Namespace{
			Inum:   ns.CgroupInum,
			IsHost: hostNs.Cgroup.Inum == ns.CgroupInum,
		},
		User: &fgs.Namespace{
			Inum:   ns.UserInum,
			IsHost: hostNs.User.Inum == ns.UserInum,
		},
	}

	// this kernel does not support time namespace
	if retVal.Time.Inum == 0 {
		retVal.Time = nil
		retVal.TimeForChildren = nil
	}

	return retVal
}
