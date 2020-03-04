package observer

import (
	"context"
	"os"
	"syscall"
	"testing"

	"github.com/covalentio/hubble-fgs/pkg/bpf"
)

var (
	observerTestDir = "/sys/fs/bpf/testObserver/"
)

func TestMain(m *testing.M) {
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.ConfigureResourceLimits()
	exitCode := m.Run()
	os.Exit(exitCode)
}

func TestObjectLoad(t *testing.T) {
	var uts syscall.Utsname

	if err := syscall.Uname(&uts); err != nil {
		t.Fatalf("sys.Uname error: %s", err)
	}

	buf := make([]byte, 65)
	for i, b := range uts.Release {
		buf[i] = byte(b)
	}
	ObserverExecve.Observer__program = "../../bpf/bpf_execve.o"
	ObserverExecveat.Observer__program = "../../bpf/bpf_execveat.o"
	ObserverFork.Observer__program = "../../bpf/bpf_fork.o"
	ObserverTCPConnect.Observer__program = "../../bpf/bpf_tcpmon.o"
	ObserverTCPConnectRet.Observer__program = "../../bpf/bpf_tcpmonret.o"
	ObserverBind.Observer__program = "../../bpf/bpf_bind.o"
	ObserverGetPort.Observer__program = "../../bpf/bpf_get_port.o"
	ObserverListen.Observer__program = "../../bpf/bpf_listen.o"
	ObserverBTF = "../../bpf/btf"

	kprobe := NewObserverKprobe(observerTestDir, false)
	kprobe.createDir()
	if err := kprobe.observerLoadExecve(context.TODO()); err != nil {
		kprobe.deleteProgs()
		t.Fatalf("observerLoadExecve error: %s", err)
	}
	if err := kprobe.observerLoadEvents(context.TODO()); err != nil {
		kprobe.deleteProgs()
		t.Fatalf("observerLoadEvents error: %s", err)
	}
	kprobe.deleteProgs()
}
