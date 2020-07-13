package observer

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/bpf"
	"github.com/covalentio/hubble-fgs/pkg/mountinfo"
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

func getDefaultObserver(t *testing.T, execve, tls, pretty bool) *ObserverKprobe {
	var uts syscall.Utsname

	if err := syscall.Uname(&uts); err != nil {
		t.Fatalf("sys.Uname error: %s", err)
	}

	buf := make([]byte, 65)
	for i, b := range uts.Release {
		buf[i] = byte(b)
	}
	if execve {
		ObserverExecve.Observer__program = "../../bpf/bpf_execve_event.o"
	} else {
		ObserverExecve.Observer__program = "../../bpf/bpf_execve.o"
	}
	ObserverFork.Observer__program = "../../bpf/bpf_fork.o"
	ObserverTCPConnect.Observer__program = "../../bpf/bpf_tcpmon.o"
	ObserverStreamConnect.Observer__program = "../../bpf/bpf_stream_connect.o"
	ObserverTCPConnectRet.Observer__program = "../../bpf/bpf_tcpmonret.o"
	ObserverBind.Observer__program = "../../bpf/bpf_bind.o"
	ObserverGetPort.Observer__program = "../../bpf/bpf_get_port.o"
	ObserverListen.Observer__program = "../../bpf/bpf_listen.o"
	btf := os.Getenv("FGS_BTF")
	if btf != "" {
		ObserverBTF = btf
	} else {
		ObserverBTF = "../../bpf/btf"
	}
	procfs := os.Getenv("FGS_PROCFS")
	if procfs != "" {
		ProcFS = procfs
	}

	kprobe := NewObserverKprobe(observerTestDir, execve, tls, pretty)
	if testing.Verbose() {
		Verbosity = 4
	}
	loadObserver(t, kprobe)

	kprobe.perfConfig = bpf.DefaultPerfEventConfig()
	kprobe.perfConfig.MapName = observerTestDir + "tcpmon_map"
	return kprobe
}

func loadObserver(t *testing.T, kprobe *ObserverKprobe) {
	kprobe.createDir()
	if err := kprobe.observerLoadExecve(context.TODO()); err != nil {
		kprobe.RemovePrograms()
		t.Fatalf("observerLoadExecve error: %s", err)
	}
}

func loopEvents(t *testing.T, exitWG, execWG *sync.WaitGroup, kprobe *ObserverKprobe, ctx context.Context) {
	exitWG.Add(1)
	execWG.Add(1)
	go func() {
		defer exitWG.Done()
		e, err := kprobe.__runEvents(ctx)
		if err != nil {
			kprobe.RemovePrograms()
			t.Fatalf("runEvents error: %s", err)
		}
		defer e.CloseAll()
		execWG.Done()
		kprobe.__loopEvents(ctx, e)
	}()
}

func TestObjectLoad(t *testing.T) {
	kprobe := getDefaultObserver(t, false, false, false)
	kprobe.observerLoadExecve(context.TODO())
	kprobe.RemovePrograms()
}

func removeMountPoint(dir string) string {
	var accum string

	dirs := strings.Split(dir, "/")
	for _, i := range dirs {
		accum += "/" + i
		pt, _, err := mountinfo.IsMountFS("", accum)
		if err != nil || pt == true {
			accum = ""
		}
	}
	return accum
}

func cwdPath() string {
	pathb := make([]byte, 1000)

	_, err := syscall.Getcwd(pathb)
	if err != nil {
		return ""
	}
	pathb = bytes.Trim(pathb, "\x00")
	path := string(pathb)
	path = removeMountPoint(path)
	path = reader.SwapPath(path)
	path = path[:len(path)-1]
	return path
}

func ipToInt(ip string) uint32 {
	ipParsed := net.ParseIP(ip)
	if ipParsed == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(ipParsed.To4())
}

func localIP() uint32 {
	return ipToInt("127.0.0.1")
}

func getMyPid() uint32 {
	if procfs := os.Getenv("FGS_PROCFS"); procfs != "" {
		procFS, _ := ioutil.ReadDir(procfs)
		for _, d := range procFS {
			if d.IsDir() == false {
				continue
			}
			cmdline, err := ioutil.ReadFile(ProcFS + d.Name() + "/cmdline")
			if err != nil {
				continue
			}
			if strings.Contains(string(cmdline), "go-build") {
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

func curlFilterR(msg *api.MsgIPv4TcpConnectUnix, k *ObserverKprobe) bool {
	var curlMsg api.MsgIPv4TcpConnectUnix

	curlMsg.Common.Op = api.MSG_OP_IPV4_TCPCONNECTRET
	curlMsg.Tuple.DAddr = localIP()
	curlMsg.Tuple.DPort = 80
	curlMsg.Tuple.Proto = 2
	curlMsg.Pid.Curr.Filename = "/usr/bin/curl"
	curlMsg.Pid.Curr.Args = "127.0.0.1\x00/" + cwdPath()
	curlMsg.Pid.Parent.PID = getMyPid()

	return k.CompareStrict(msg, &curlMsg)
}

func curlExecFilterR(msg *api.MsgIPv4TcpConnectUnix, k *ObserverKprobe) bool {
	var curlMsg api.MsgIPv4TcpConnectUnix

	curlMsg.Common.Op = api.MSG_OP_EXECVE
	curlMsg.Pid.Curr.Filename = "/usr/bin/curl"
	curlMsg.Pid.Curr.Args = "127.0.0.1\x00/" + cwdPath()
	curlMsg.Pid.Parent.PID = getMyPid()

	return k.CompareStrict(msg, &curlMsg)
}

func execWGCurl(execWG, exitWG *sync.WaitGroup, args string) {
	execWG.Wait()
	cmd := exec.Command("/usr/bin/curl", args)
	err := cmd.Run()
	fmt.Printf("cmd %v err %v\n", cmd, err)
	exitWG.Wait()
}

func testDone(t *testing.T, kprobe *ObserverKprobe) {
	kprobe.RemovePrograms()
	kprobe.PrintStats()
	if kprobe.filterPass < 1 {
		t.Fail()
	}
}

func TestConnectEvent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10000*time.Millisecond)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	kprobe := getDefaultObserver(t, false, false, true)
	kprobe.AttachFilter(&MsgFilter{run: curlFilterR})

	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWGCurl(&execWG, &exitWG, "127.0.0.1")
	testDone(t, kprobe)
}

func TestExecEvent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10000*time.Millisecond)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	kprobe := getDefaultObserver(t, true, false, true)
	kprobe.AttachFilter(&MsgFilter{run: curlExecFilterR})

	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWGCurl(&execWG, &exitWG, "127.0.0.1")
	testDone(t, kprobe)
}

func ncExecFilterR(msg *api.MsgIPv4TcpConnectUnix, k *ObserverKprobe) bool {
	var filterMsg api.MsgIPv4TcpConnectUnix

	ncPath, _ := exec.LookPath("nc.traditional")
	filterMsg.Common.Op = api.MSG_OP_EXECVE
	filterMsg.Pid.Curr.Filename = ncPath
	filterMsg.Pid.Curr.Args = "127.0.0.1\x008081\x00-e\x00/bin/sh\x00/" + cwdPath()
	filterMsg.Pid.Parent.PID = getMyPid()

	return k.CompareStrict(msg, &filterMsg)
}

func ncListenR(msg *api.MsgIPv4TcpConnectUnix, k *ObserverKprobe) bool {
	var filterMsg api.MsgIPv4TcpConnectUnix

	ncPath, _ := exec.LookPath("nc.traditional")
	filterMsg.Common.Op = api.MSG_OP_IPV4_LISTEN
	filterMsg.Tuple.SPort = 8081
	filterMsg.Tuple.Proto = 2
	filterMsg.Pid.Curr.Filename = ncPath
	filterMsg.Pid.Curr.Args = "-nvlp\x008081\x00/" + cwdPath()
	filterMsg.Pid.Parent.PID = getMyPid()

	return k.CompareStrict(msg, &filterMsg)
}

func ncExecRunningR(msg *api.MsgIPv4TcpConnectUnix, k *ObserverKprobe) bool {
	var filterMsg api.MsgIPv4TcpConnectUnix

	path, _ := os.Getwd()
	ncPath, _ := exec.LookPath("nc.traditional")
	filterMsg.Common.Op = api.MSG_OP_EXECVE
	filterMsg.Pid.Curr.Filename = ncPath
	filterMsg.Pid.Curr.Args = "-nvlp\x008081\x00 " + path
	filterMsg.Pid.Parent.PID = getMyPid()

	return k.CompareStrict(msg, &filterMsg)
}

func ncListenRunningR(msg *api.MsgIPv4TcpConnectUnix, k *ObserverKprobe) bool {
	var filterMsg api.MsgIPv4TcpConnectUnix

	path, _ := os.Getwd()
	ncPath, _ := exec.LookPath("nc.traditional")
	filterMsg.Common.Op = api.MSG_OP_IPV4_LISTEN
	filterMsg.Tuple.SPort = 8081
	filterMsg.Tuple.Proto = 2
	filterMsg.Pid.Curr.Filename = ncPath
	/* Put Args in format received by existing event */
	filterMsg.Pid.Curr.Args = "-nvlp\x008081\x00 " + path
	filterMsg.Pid.Parent.PID = getMyPid()

	return k.CompareStrict(msg, &filterMsg)
}

func ncExecRunningRootR(msg *api.MsgIPv4TcpConnectUnix, k *ObserverKprobe) bool {
	var filterMsg api.MsgIPv4TcpConnectUnix

	ncPath, _ := exec.LookPath("nc.traditional")
	filterMsg.Common.Op = api.MSG_OP_EXECVE
	filterMsg.Pid.Curr.Filename = ncPath
	filterMsg.Pid.Curr.Args = "-nvlp\x008081\x00"
	filterMsg.Pid.Parent.PID = getMyPid()

	return k.CompareStrict(msg, &filterMsg)
}

func ncListenRunningRootR(msg *api.MsgIPv4TcpConnectUnix, k *ObserverKprobe) bool {
	var filterMsg api.MsgIPv4TcpConnectUnix

	ncPath, _ := exec.LookPath("nc.traditional")
	filterMsg.Common.Op = api.MSG_OP_IPV4_LISTEN
	filterMsg.Tuple.SPort = 8081
	filterMsg.Tuple.Proto = 2
	filterMsg.Pid.Curr.Filename = ncPath
	filterMsg.Pid.Curr.Args = "-nvlp\x008081\x00"
	filterMsg.Pid.Parent.PID = getMyPid()

	return k.CompareStrict(msg, &filterMsg)
}

func ncConnectR(msg *api.MsgIPv4TcpConnectUnix, k *ObserverKprobe) bool {
	var filterMsg api.MsgIPv4TcpConnectUnix

	ncPath, _ := exec.LookPath("nc.traditional")
	filterMsg.Common.Op = api.MSG_OP_IPV4_TCPCONNECTRET
	filterMsg.Tuple.DPort = 8081
	filterMsg.Tuple.DAddr = localIP()
	filterMsg.Tuple.Proto = 2
	filterMsg.Pid.Curr.Filename = ncPath
	filterMsg.Pid.Curr.Args = "127.0.0.1\x008081\x00-e\x00/bin/sh\x00/" + cwdPath()
	filterMsg.Pid.Parent.PID = getMyPid()

	return k.CompareStrict(msg, &filterMsg)
}

func ncExecCloneFilterR(msg *api.MsgIPv4TcpConnectUnix, k *ObserverKprobe) bool {
	var filterMsg api.MsgIPv4TcpConnectUnix

	filterMsg.Common.Op = api.MSG_OP_EXECVE
	filterMsg.Pid.Curr.Filename = "/bin/sh"
	filterMsg.Pid.Curr.Args = "/" + cwdPath()
	filterMsg.Pid.Curr.Flags = api.EventExecve
	filterMsg.Pid.Parent.PID = getMyPid()

	return k.CompareStrict(msg, &filterMsg)
}

func filterPassCheck(t *testing.T, f *MsgFilter, pass int) {
	fmt.Printf("f.filterPass %d\n", f.filterPass)
	if f.filterPass != pass {
		t.Fail()
	}
}

func TestExecEventClone(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10000*time.Millisecond)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	kprobe := getDefaultObserver(t, true, false, true)

	ncExecFilter := MsgFilter{run: ncExecFilterR}
	ncListen := MsgFilter{run: ncListenR}
	ncConnect := MsgFilter{run: ncConnectR}
	ncExecCloneFilter := MsgFilter{run: ncExecCloneFilterR}

	/* Verify initial KprobeEvent Execve "nc.traditional 127.0.0.1 8081 -e /bin/sh" */
	kprobe.AttachFilter(&ncExecFilter)
	/* Verify KprobeEvent TCPConnectReturn "nc.traditional 127.0.0.1 8081 -e /bin/sh" */
	kprobe.AttachFilter(&ncListen)
	kprobe.AttachFilter(&ncConnect)
	/* Verify KprobeEvent Execve '-e /bin/sh' without clone() */
	kprobe.AttachFilter(&ncExecCloneFilter)

	loopEvents(t, &exitWG, &execWG, kprobe, ctx)

	execWG.Wait()
	cmdServer := exec.Command("nc.traditional", "-nvlp", "8081")
	cmdServer.Start()
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command("nc.traditional", "127.0.0.1", "8081", "-e", "/bin/sh")
	cmdClient.Start()
	exitWG.Wait()

	if cmdServer != nil {
		cmdServer.Process.Kill()
	}
	if cmdClient != nil {
		cmdClient.Process.Kill()
	}

	filterPassCheck(t, &ncExecFilter, 1)
	filterPassCheck(t, &ncListen, 1)
	filterPassCheck(t, &ncConnect, 1)
	filterPassCheck(t, &ncExecCloneFilter, 1)
	testDone(t, kprobe)
}

func TestExistingListenEvent(t *testing.T) {
	/* Start server before creating kprobe */
	cmdServer := exec.Command("nc.traditional", "-nvlp", "8081")
	cmdServer.Start()

	/* Create kprobe */
	kprobe := getDefaultObserver(t, true, false, false)

	ncExecFilter := MsgFilter{run: ncExecRunningR}
	ncListen := MsgFilter{run: ncListenRunningR}
	kprobe.AttachFilter(&ncExecFilter)
	kprobe.AttachFilter(&ncListen)

	kprobe.getRunningProcs(false, true)

	if cmdServer != nil {
		cmdServer.Process.Kill()
	}
	filterPassCheck(t, &ncExecFilter, 1)
	filterPassCheck(t, &ncListen, 1)
	testDone(t, kprobe)
}

func TestExistingRootCWDListenEvent(t *testing.T) {
	path, err := os.Getwd()
	if err != nil {
		t.Fail()
	}

	/* Start server in '/' before creating kprobe */
	os.Chdir("/")
	cmdServer := exec.Command("nc.traditional", "-nvlp", "8081")
	cmdServer.Start()
	os.Chdir(path)

	/* Create kprobe */
	kprobe := getDefaultObserver(t, true, false, false)

	ncExecFilter := MsgFilter{run: ncExecRunningRootR}
	ncListen := MsgFilter{run: ncListenRunningRootR}
	kprobe.AttachFilter(&ncExecFilter)
	kprobe.AttachFilter(&ncListen)

	kprobe.getRunningProcs(false, true)

	if cmdServer != nil {
		cmdServer.Process.Kill()
	}
	filterPassCheck(t, &ncExecFilter, 1)
	filterPassCheck(t, &ncListen, 1)
	testDone(t, kprobe)
}
