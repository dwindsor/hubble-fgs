package observer

import (
	"github.com/covalentio/hubble-fgs/pkg/api"

	"fmt"
)

func (k *ObserverKprobe) Printf(format string, a ...interface{}) (n int, err error) {
	if Verbosity < 4 {
		return 0, nil
	}

	return fmt.Printf(format, a...)
}

func (k *ObserverKprobe) CompareCommonStrict(x, y *api.MsgCommon) bool {
	if y.Op != 0 && y.Op != x.Op {
		return false
	}
	return true
}

func (k *ObserverKprobe) CompareTcpConnectStrict(x, y *api.MsgIPv4Tuple) bool {
	if y.SAddr != 0 && y.SAddr != x.SAddr {
		k.Printf("y.SAddr != x.Saddr %d != %d\n", y.SAddr, x.SAddr)
		return false
	}
	if y.DAddr != 0 && y.DAddr != x.DAddr {
		k.Printf("y.DAddr != x.DAddr %d != %d\n", y.DAddr, x.DAddr)
		return false
	}
	if y.DPort != 0 && y.DPort != api.SwapByte(x.DPort) {
		k.Printf("y.DPort != x.DPort %d != %d\n", y.DPort, x.DPort)
		return false
	}
	if y.SPort != 0 && y.SPort != x.SPort {
		k.Printf("y.SPort != x.SPort %d != %d\n", y.SPort, x.SPort)
		return false
	}
	if y.Proto != 0 && y.Proto != x.Proto {
		k.Printf("y.Proto != x.Proto %d != %d\n", y.Proto, x.Proto)
		return false
	}
	return true
}

func (k *ObserverKprobe) CompareK8sStrict(x, y *api.MsgK8sUnix) bool {
	if y.NetNS != 0 && y.NetNS != x.NetNS {
		k.Printf("y.NetNS != x.NetNS %d != %d\n", y.NetNS, x.NetNS)
		return false
	}
	if y.Cid != 0 && y.Cid != x.Cid {
		k.Printf("y.Cid != x.Cid %d != %d\n", y.Cid, x.Cid)
		return false
	}
	if y.Cgrpid != 0 && y.Cgrpid != x.Cgrpid {
		k.Printf("y.Cgrpid != x.Cgrpid %d != %d\n", y.Cgrpid, x.Cgrpid)
		return false
		return false
	}
	if y.Docker != "" && y.Docker != x.Docker {
		k.Printf("y.Docker != x.Docker %s != %s\n", y.Docker, x.Docker)
		return false
	}
	return true
}

func (k *ObserverKprobe) CompareMsgExecStrict(x, y *api.MsgExecUnix) bool {
	if y.Size != 0 && y.Size != x.Size {
		k.Printf("y.Size != x.Size %d != %d\n", y.Size, x.Size)
		return false
	}
	if y.PID != 0 && y.PID != x.PID {
		k.Printf("y.PID != x.PID %d != %d\n", y.PID, x.PID)
		return false
	}
	if y.UID != 0 && y.UID != x.UID {
		k.Printf("y.UID != x.UID %d != %d\n", y.UID, x.UID)
		return false
	}
	if y.AUID != 0 && y.AUID != x.AUID {
		k.Printf("y.AUID != x.AUID %d != %d\n", y.AUID, x.AUID)
		return false
	}
	if y.Flags != 0 && y.Flags != x.Flags {
		k.Printf("y.Filename != x.Filename %s != %s\n", y.Filename, x.Filename)
		k.Printf("y.Flags != x.Flags %d != %d\n", y.Flags, x.Flags)
		k.Printf("y.Args %s != x.Args %s\n", y.Args, x.Args)
		return false
	}
	if y.Ktime != 0 && y.Ktime != x.Ktime {
		k.Printf("y.Ktime != x.Ktime %d != %d\n", y.Ktime, x.Ktime)
		return false
	}
	if y.Filename != "" && y.Filename != x.Filename {
		k.Printf("y.Filename != x.Filename %s != %s\n", y.Filename, x.Filename)
		return false
	}
	if y.Args != "" && y.Args != x.Args {
		k.Printf("y.Args %s != x.Args %s\n", y.Args, x.Args)
		return false
	}
	return true
}

func (k *ObserverKprobe) ComparePidStrict(x, y *api.MsgPidUnix) bool {
	if res := k.CompareMsgExecStrict(&x.Parent, &y.Parent); res == false {
		return false
	}
	if res := k.CompareMsgExecStrict(&x.Curr, &y.Curr); res == false {
		return false
	}
	return true
}

func (k *ObserverKprobe) CompareStrict(x, y *api.MsgIPv4TcpEventUnix) bool {
	if res := k.CompareCommonStrict(&x.Common, &y.Common); res == false {
		return false
	}

	if res := k.CompareTcpConnectStrict(&x.Tuple, &y.Tuple); res == false {
		return false
	}
	if res := k.CompareK8sStrict(&x.Kube, &y.Kube); res == false {
		return false
	}
	return true
}
