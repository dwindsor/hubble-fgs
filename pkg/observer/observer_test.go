package observer

import (
	"bytes"
	"context"
	"os"
	"strings"
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
	uname := strings.TrimSpace(string(bytes.Trim(buf, "\x00")))
	ObserverExecve.Observer__program = "../../bpf/bins/bpf_execve_" + uname + ".o"
	ObserverExecveat.Observer__program = "../../bpf/bins/bpf_execveat_" + uname + ".o"
	ObserverFork.Observer__program = "../../bpf/bins/bpf_fork_" + uname + ".o"
	ObserverTCPConnect.Observer__program = "../../bpf/bins/bpf_tcpmon_" + uname + ".o"
	ObserverTCPConnectRet.Observer__program = "../../bpf/bins/bpf_tcpmonret_" + uname + ".o"
	ObserverBind.Observer__program = "../../bpf/bins/bpf_bind_" + uname + ".o"
	ObserverListen.Observer__program = "../../bpf/bins/bpf_listen_" + uname + ".o"

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
