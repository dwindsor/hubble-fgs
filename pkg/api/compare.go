package api

import (
	"fmt"
)

func CompareCommonStrict(x, y *MsgCommon) bool {
	if y.Op != 0 && y.Op != x.Op {
		return false
	}
	return true
}

func CompareTcpConnectStrict(x, y *MsgIPv4Tuple) bool {
	if y.SAddr != 0 && y.SAddr != x.SAddr {
		fmt.Printf("y.SAddr != x.Saddr %d != %d\n", y.SAddr, x.SAddr)
		return false
	}
	if y.DAddr != 0 && y.DAddr != x.DAddr {
		fmt.Printf("y.DAddr != x.DAddr %d != %d\n", y.DAddr, x.DAddr)
		return false
	}
	if y.DPort != 0 && y.DPort != SwapByte(x.DPort) {
		fmt.Printf("y.DPort != x.DPort %d != %d\n", y.DPort, x.DPort)
		return false
	}
	if y.SPort != 0 && y.SPort != x.SPort {
		fmt.Printf("y.SPort != x.SPort %d != %d\n", y.SPort, x.SPort)
		return false
	}
	if y.Proto != 0 && y.Proto != x.Proto {
		fmt.Printf("y.Proto != x.Proto %d != %d\n", y.Proto, x.Proto)
		return false
	}
	return true
}

func CompareK8sStrict(x, y *MsgK8sUnix) bool {
	if y.NetNS != 0 && y.NetNS != x.NetNS {
		fmt.Printf("y.NetNS != x.NetNS %d != %d\n", y.NetNS, x.NetNS)
		return false
	}
	if y.Cid != 0 && y.Cid != x.Cid {
		fmt.Printf("y.Cid != x.Cid %d != %d\n", y.Cid, x.Cid)
		return false
	}
	if y.Cgrpid != 0 && y.Cgrpid != x.Cgrpid {
		fmt.Printf("y.Cgrpid != x.Cgrpid %d != %d\n", y.Cgrpid, x.Cgrpid)
		return false
		return false
	}
	if y.Docker != "" && y.Docker != x.Docker {
		fmt.Printf("y.Docker != x.Docker %s != %s\n", y.Docker, x.Docker)
		return false
	}
	return true
}

func CompareMsgExecStrict(x, y *MsgExecUnix) bool {
	if y.Size != 0 && y.Size != x.Size {
		fmt.Printf("y.Size != x.Size %d != %d\n", y.Size, x.Size)
		return false
	}
	if y.PID != 0 && y.PID != x.PID {
		fmt.Printf("y.PID != x.PID %d != %d\n", y.PID, x.PID)
		return false
	}
	if y.UID != 0 && y.UID != x.UID {
		fmt.Printf("y.UID != x.UID %d != %d\n", y.UID, x.UID)
		return false
	}
	if y.AUID != 0 && y.AUID != x.AUID {
		fmt.Printf("y.AUID != x.AUID %d != %d\n", y.AUID, x.AUID)
		return false
	}
	if y.Flags != 0 && y.Flags != x.Flags {
		fmt.Printf("y.Flags != x.Flags %d != %d\n", y.Flags, x.Flags)
		return false
	}
	if y.Ktime != 0 && y.Ktime != x.Ktime {
		fmt.Printf("y.Ktime != x.Ktime %d != %d\n", y.Ktime, x.Ktime)
		return false
	}
	if y.Filename != "" && y.Filename != x.Filename {
		fmt.Printf("y.Filename != x.Filename %s != %s\n", y.Filename, x.Filename)
		return false
	}
	if y.Args != "" && y.Args != x.Args {
		fmt.Printf("y.Args %s != x.Args %s\n", y.Args, x.Args)
		return false
	}
	return true
}

func ComparePidStrict(x, y *MsgPidUnix) bool {
	if res := CompareMsgExecStrict(&x.Parent, &y.Parent); res == false {
		return false
	}
	if res := CompareMsgExecStrict(&x.Curr, &y.Curr); res == false {
		return false
	}
	return true
}

func CompareStrict(x, y *MsgIPv4TcpConnectUnix) bool {
	if res := CompareCommonStrict(&x.Common, &y.Common); res == false {
		return false
	}

	if res := CompareTcpConnectStrict(&x.Tuple, &y.Tuple); res == false {
		return false
	}
	if res := CompareK8sStrict(&x.Kube, &y.Kube); res == false {
		return false
	}
	if res := ComparePidStrict(&x.Pid, &y.Pid); res == false {
		return false
	}
	return true
}
