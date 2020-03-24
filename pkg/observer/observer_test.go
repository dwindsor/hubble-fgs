package observer

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"

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

func getDefaultObserver(t *testing.T) *ObserverKprobe {
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

	return NewObserverKprobe(observerTestDir, false)
}

func loadObserver(t *testing.T, kprobe *ObserverKprobe) {
	kprobe.createDir()
	if err := kprobe.observerLoadExecve(context.TODO()); err != nil {
		kprobe.deleteProgs()
		t.Fatalf("observerLoadExecve error: %s", err)
	}
}

func loadEvents(t *testing.T, kprobe *ObserverKprobe) {
	if err := kprobe.observerLoadEvents(context.TODO()); err != nil {
		kprobe.deleteProgs()
		t.Fatalf("observerLoadEvents error: %s", err)
	}
}

func TestObjectLoad(t *testing.T) {
	kprobe := getDefaultObserver(t)
	loadObserver(t, kprobe)
	loadEvents(t, kprobe)
	kprobe.deleteProgs()
}

func TestConnectEvent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10000*time.Millisecond)
	defer cancel()

	kprobe := getDefaultObserver(t)
	loadObserver(t, kprobe)

	kprobe.perfConfig = bpf.DefaultPerfEventConfig()
	kprobe.perfConfig.MapName = observerTestDir + "tcpmon_map"
	if err := kprobe.runEvents(ctx); err != nil {
		kprobe.deleteProgs()
		t.Fatalf("runEvents error: %s", err)
	}
	kprobe.deleteProgs()
	kprobe.PrintStats()
}
