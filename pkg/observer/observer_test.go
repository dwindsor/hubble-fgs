package observer

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/bpf"
	"github.com/covalentio/hubble-fgs/pkg/reader"
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

func getDefaultObserver(t *testing.T, pretty bool) *ObserverKprobe {
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

	return NewObserverKprobe(observerTestDir, pretty)
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
	kprobe := getDefaultObserver(t, false)
	loadObserver(t, kprobe)
	loadEvents(t, kprobe)
	kprobe.deleteProgs()
}

func curlFilter(msg *api.MsgIPv4TcpConnectUnix) bool {
	var curlMsg api.MsgIPv4TcpConnectUnix

	ip := net.ParseIP("127.0.0.1")
	if ip == nil {
		return false
	}
	ip = ip.To4()

	path, err := os.Getwd()
	if err != nil {
		return false
	}
	path = reader.SwapPath(path)
	path = path[:len(path)-1]

	curlMsg.Common.Op = api.MSG_OP_IPV4_TCPCONNECTRET
	curlMsg.Tuple.DAddr = binary.LittleEndian.Uint32(ip)
	curlMsg.Tuple.DPort = 80
	curlMsg.Tuple.Proto = 2
	curlMsg.Pid.Curr.Filename = "/usr/bin/curl"
	curlMsg.Pid.Curr.Args = "127.0.0.1\x00/" + path
	curlMsg.Pid.Parent.PID = uint32(os.Getpid())

	return api.CompareStrict(msg, &curlMsg)
}

func execCurl(args string) {
	cmd := exec.Command("/usr/bin/curl", args)
	err := cmd.Run()
	fmt.Printf("cmd %v err %v\n", cmd, err)
}

func TestConnectEvent(t *testing.T) {
	var exitWG, execWG sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 10000*time.Millisecond)
	defer cancel()

	kprobe := getDefaultObserver(t, true)
	loadObserver(t, kprobe)

	kprobe.perfConfig = bpf.DefaultPerfEventConfig()
	kprobe.perfConfig.MapName = observerTestDir + "tcpmon_map"
	kprobe.AttachFilter(curlFilter)

	exitWG.Add(1)
	execWG.Add(1)
	go func() {
		defer exitWG.Done()
		e, err := kprobe.__runEvents(ctx)
		if err != nil {
			kprobe.deleteProgs()
			t.Fatalf("runEvents error: %s", err)
		}
		defer e.CloseAll()
		execWG.Done()
		kprobe.__loopEvents(ctx, e)
	}()
	execWG.Wait()
	execCurl("127.0.0.1")
	exitWG.Wait()
	kprobe.deleteProgs()
	kprobe.PrintStats()
	if kprobe.filterPass < 1 {
		t.Fail()
	}
}
