package observer

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	hubbleCilium "github.com/cilium/hubble/pkg/cilium"

	"github.com/covalentio/hubble-fgs/api/v1/fgs"
	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/bpf"
	"github.com/covalentio/hubble-fgs/pkg/cilium"
	fgsGrpc "github.com/covalentio/hubble-fgs/pkg/grpc"
	"github.com/covalentio/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/covalentio/hubble-fgs/pkg/mountinfo"
	"github.com/covalentio/hubble-fgs/pkg/reader"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/stretchr/testify/assert"

	hubbleV1 "github.com/cilium/hubble/pkg/api/v1"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	selfBinary   string
	fgsLib       string
	cmdWaitTime  time.Duration
	verboseLevel int
)

const (
	testConfigFile = "/tmp/hubble-fgs.gotest.yaml"
)

func init() {
	flag.StringVar(&fgsLib, "hubble-lib", "../../bpf/objs/", "hubble lib directory (location of btf file and bpf objs). Will be overridden by an FGS_LIB env variable.")
	flag.DurationVar(&cmdWaitTime, "command-wait", 20000*time.Millisecond, "duration to wait for fgs to gather logs from commands")
	flag.IntVar(&verboseLevel, "verbosity-level", 0, "verbosity level of verbose mode. (Requires verbose mode to be enabled.)")

}

func TestMain(m *testing.M) {
	flag.Parse()
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.ConfigureResourceLimits()
	selfBinary = filepath.Base(os.Args[0])
	exitCode := m.Run()
	os.Exit(exitCode)
}

func getDefaultObserver(t *testing.T, opts ...testOption) (*ObserverKprobe, error) {
	ctx, _ := context.WithCancel(context.Background())
	var uts syscall.Utsname

	if err := syscall.Uname(&uts); err != nil {
		t.Fatalf("sys.Uname error: %s", err)
	}

	buf := make([]byte, 65)
	for i, b := range uts.Release {
		buf[i] = byte(b)
	}

	HubbleLib = fgsLib
	envFgsLib := os.Getenv("FGS_LIB")
	if envFgsLib != "" {
		HubbleLib = envFgsLib
	}
	procfs := os.Getenv("FGS_PROCFS")
	if procfs != "" {
		ProcFS = procfs
	}

	// default values
	o := &testOptions{
		observer: testObserverOptions{
			tls:    false,
			tlstc:  false,
			pretty: false,
			crd:    false,
			config: "",
		},
		exporter: testExporterOptions{
			watcher:     fgsGrpc.NewFakeK8sWatcher(nil),
			ciliumState: cilium.GetFakeCiliumState(),
		},
	}
	// apply user options
	for _, opt := range opts {
		opt(o)
	}

	oo := &o.observer
	kprobe := NewObserverKprobe(observerTestDir,
		observerTestDir,
		"", "",
		oo.config, oo.tracepoints, oo.tls, oo.tlstc, oo.pretty, oo.crd)
	if testing.Verbose() {
		Verbosity = verboseLevel
	}

	err := kprobe.ConfigureBTF(ctx)
	if err != nil {
		return nil, err
	}
	if err := kprobe.observerFindProgs(ctx); err != nil {
		return nil, err
	}

	loadExporter(t, kprobe, &o.exporter)
	loadObserver(t, kprobe)

	kprobe.perfConfig = bpf.DefaultPerfEventConfig()
	kprobe.perfConfig.MapName = observerTestDir + "tcpmon_map"
	return kprobe, nil
}

func TestObjectLoad(t *testing.T) {
	kprobe, err := getDefaultObserver(t)
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
	}
	initialSensor := kprobe.createInitialObserverSensor()
	kprobe.observerLoadSensor(context.TODO(), initialSensor)
	kprobe.RemovePrograms()
}

func TestKprobeObjectLoad(t *testing.T) {
	writeReadHook := `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_write"
spec:
  description: "write hook"
  kprobes:
  - call: "__x64_sys_write"
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
      sizeargindex: 2
    - index: 2
      type: "size_t"
    allowfilters:
      pids:
      - op: "eq"
        value: 25587
      args:
      - index: 0
        op: "eq"
        value: "1"
`
	writeConfigHook := []byte(writeReadHook)
	err := ioutil.WriteFile(testConfigFile, writeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	kprobe, err := getDefaultObserver(t, withConfig(testConfigFile))
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
	}
	initialSensor := kprobe.createInitialObserverSensor()
	kprobe.observerLoadSensor(context.TODO(), initialSensor)
	kprobe.RemovePrograms()
}

// NB: This is similar to TestKprobeObjectWriteRead, but it's a bit easier to
// debug because we can write things on stdout which will not generate events.
func TestKprobeLseek(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10000*time.Millisecond)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	pidStr := strconv.Itoa(int(getMyPid()))
	fmt.Printf("pid=%s\n", pidStr)

	lseekConfigHook_ := `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_write"
spec:
  description: "lseek hook"
  kprobes:
  - call: "__x64_sys_lseek"
    return: false
    syscall: true
    args:
    - index: 0
      type: "int"
    allowfilters:
      pids:
      - op: "eq"
        value: ` + pidStr + ` 
        followforks: true
        isnamespacepid: false 
`
	lseekConfigHook := []byte(lseekConfigHook_)
	err := ioutil.WriteFile(testConfigFile, lseekConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	kprobe, err := getDefaultObserverWithWatchers(t, withConfig(testConfigFile))
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
	}
	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWG.Wait()
	fmt.Printf("Calling lseek...\n")
	unix.Seek(-1, 0, 4444)
	exitWG.Wait()
	testDone(t, kprobe)
}

func TestKprobeObjectWriteRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10000*time.Millisecond)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	pidStr := strconv.Itoa(int(getMyPid()))
	writeReadHook := `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_write"
spec:
  description: "write hook"
  kprobes:
  - call: "__x64_sys_write"
    return: false 
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
      sizeargindex: 3
    - index: 2
      type: "size_t"
    allowfilters:
      pids:
      - op: "eq"
        value: ` + pidStr + ` 
        followforks: true
        isnamespacepid: false 
      args:
      - index: 0
        op: "eq"
        value: "1"
`
	writeConfigHook := []byte(writeReadHook)
	err := ioutil.WriteFile(testConfigFile, writeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	arg0 := &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_IntArg{IntArg: 1}}
	arg1 := &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_StringArg{StringArg: "hello world"}}
	arg2 := &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_SizeArg{SizeArg: 11}}

	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &fgs.ProcessKprobe{
					Process:      &fgs.Process{Binary: selfBinary},
					Parent:       &fgs.Process{Binary: ""},
					FunctionName: "__x64_sys_write",
					Args:         []*fgs.KprobeArgument{arg0, arg1, arg2},
				},
			},
		},
	}

	kprobe, err := getDefaultObserverWithWatchers(t, withConfig(testConfigFile))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWG.Wait()
	_, err = syscall.Write(1, []byte("hello world"))
	exitWG.Wait()
	retries := jsonRetries
	time.Sleep(1000 * time.Millisecond)
	if ok := jsonTestCompare(trace, nil, retries, 0); !ok {
		t.Fail()
	}
	testDone(t, kprobe)
}

func TestKprobeObjectRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10000*time.Millisecond)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	// Create file with hello world to read
	fd, errno := syscall.Open("/tmp/testfile", syscall.O_CREAT|syscall.O_RDWR, 0x777)
	if fd < 0 {
		fmt.Printf("File open failed: %s\n", errno)
		t.Fatal()
	}
	fd2, errno := syscall.Open("/tmp/testfile", syscall.O_RDWR, 0x770)
	if fd2 < 0 {
		fmt.Printf("File open fro read failed: %s\n", errno)
		t.Fatal()
	}
	fdString := fmt.Sprint(fd2)
	pidStr := strconv.Itoa(int(getMyPid()))
	readHook := `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_read"
spec:
  description: "read hook"
  kprobes:
  - call: "__x64_sys_read"
    return: true
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
      returncopy: true
    - index: 2
      type: "size_t"
    allowfilters:
      pids:
      - op: "eq"
        value: ` + pidStr + `
        followforks: true
        isnamespacepid: false
      args:
      - index: 0
        op: "eq"
        value: ` + fdString + `
`
	readConfigHook := []byte(readHook)
	err := ioutil.WriteFile(testConfigFile, readConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	arg0 := &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_StringArg{StringArg: "hello world"}}
	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &fgs.ProcessKprobe{
					Process:      &fgs.Process{Binary: selfBinary},
					Parent:       &fgs.Process{Binary: ""},
					FunctionName: "__x64_sys_read",
					Args:         []*fgs.KprobeArgument{arg0},
				},
			},
		},
	}
	kprobe, err := getDefaultObserverWithWatchers(t, withConfig(testConfigFile))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWG.Wait()
	hello := []byte("hello world")
	n, errno := syscall.Write(fd, hello)
	if n < 0 {
		fmt.Printf("syscall.Write failed: %s\n", errno)
		t.Fatal()
	}
	syscall.Fsync(fd)
	var readBytes = make([]byte, 11)
	i, errno := syscall.Read(fd2, readBytes)
	if i < 0 {
		fmt.Printf("syscall.Read failed: %s\n", errno)
		t.Fatal()
	}
	exitWG.Wait()
	retries := jsonRetries
	time.Sleep(1000 * time.Millisecond)
	if ok := jsonTestCompare(trace, nil, retries, 0); !ok {
		t.Fail()
	}
	testDone(t, kprobe)
}

func helloIovecWorldWritev() (err error) {
	var arrayOfBytes = make([][]byte, 3)

	h := []byte("hello")
	i := []byte(" iovec ")
	w := []byte("world")

	arrayOfBytes[0] = h
	arrayOfBytes[1] = i
	arrayOfBytes[2] = w
	_, err = unix.Writev(1, arrayOfBytes)
	return err
}

func TestKprobeObjectWriteVRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10000*time.Millisecond)
	var exitWG, execWG sync.WaitGroup
	defer cancel()
	pidStr := strconv.Itoa(int(getMyPid()))

	writeReadHook := `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "__x64_sys_writev"
spec:
  description: "write hook"
  kprobes:
  - call: "__x64_sys_writev"
    return: false
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_iovec"
      sizeargindex: 3
    allowfilters:
      pids:
      - op: "eq"
        value: ` + pidStr + ` 
        followforks: true
        isnamespacepid: false 
      args:
      - index: 0
        op: "eq"
        value: "1"
`
	writeConfigHook := []byte(writeReadHook)
	err := ioutil.WriteFile(testConfigFile, writeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	arg0 := &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_IntArg{IntArg: 1}}
	arg1 := &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_StringArg{StringArg: "hello iovec world"}}

	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &fgs.ProcessKprobe{
					Process:      &fgs.Process{Binary: selfBinary},
					Parent:       &fgs.Process{Binary: ""},
					FunctionName: "__x64_sys_writev",
					Args:         []*fgs.KprobeArgument{arg0, arg1},
				},
			},
		},
	}

	kprobe, err := getDefaultObserverWithWatchers(t, withConfig(testConfigFile))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWG.Wait()
	err = helloIovecWorldWritev()
	execWG.Wait()
	retries := jsonRetries
	time.Sleep(1000 * time.Millisecond)
	if ok := jsonTestCompare(trace, nil, retries, 0); !ok {
		t.Fail()
	}
	testDone(t, kprobe)
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

func cwdPath(swap bool) string {
	pathb := make([]byte, 1000)

	_, err := syscall.Getcwd(pathb)
	if err != nil {
		return ""
	}
	pathb = bytes.Trim(pathb, "\x00")
	path := string(pathb)
	path = removeMountPoint(path)
	if swap {
		path = reader.SwapPath(path)
		if len(path) > 0 {
			path = path[:len(path)-1]
		}
	}
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

func testDone(t *testing.T, kprobe *ObserverKprobe) {
	kprobe.RemovePrograms()
	kprobe.PrintStats()
}

func TestConnectEvent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{Binary: selfBinary},
					Parent:  &fgs.Process{Binary: ""},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{
						Binary:    "curl",
						Arguments: "127.0.0.1"},
					Parent: &fgs.Process{Binary: selfBinary},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessConnect{
				ProcessConnect: &fgs.ProcessConnect{
					Process: &fgs.Process{
						Binary:    "curl",
						Arguments: "127.0.0.1"},
					Parent: &fgs.Process{
						Binary: selfBinary},
					DestinationIp:   "127.0.0.1",
					DestinationPort: &wrappers.UInt32Value{Value: 80},
				},
			},
		},
	}

	kprobe, err := getDefaultObserverWithWatchers(t, withPretty())
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}

	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWGCurl(&execWG, &exitWG, "127.0.0.1")
	retries := jsonRetries
	if ok := jsonTestCompare(trace, nil, retries, 0); !ok {
		t.Fail()
	}
	testDone(t, kprobe)
}

func TestExecEventClone(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	rcwd := cwdPath(true)
	fcwd := cwdPath(false)

	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{Binary: selfBinary},
					Parent:  &fgs.Process{Binary: ""},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{
						Binary:    "nc.traditional",
						Arguments: "-nvlp 8081",
						Cwd:       fcwd},
					Parent: &fgs.Process{Binary: selfBinary,
						Cwd: rcwd},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessListen{
				ProcessListen: &fgs.ProcessListen{
					Process: &fgs.Process{
						Binary:    "nc.traditional",
						Arguments: "-nvlp 8081",
						Cwd:       fcwd},
					Parent: &fgs.Process{
						Binary: selfBinary,
						Cwd:    rcwd},
					Ip:   "0.0.0.0",
					Port: &wrappers.UInt32Value{Value: 8081},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{
						Binary:    "nc.traditional",
						Arguments: "127.0.0.1 8081 -e /bin/sh",
						Cwd:       fcwd},
					Parent: &fgs.Process{
						Binary: selfBinary,
						Cwd:    rcwd},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessConnect{
				ProcessConnect: &fgs.ProcessConnect{
					Process: &fgs.Process{
						Binary:    "nc.traditional",
						Arguments: "127.0.0.1 8081 -e /bin/sh",
						Cwd:       fcwd},
					Parent: &fgs.Process{
						Binary: selfBinary,
						Cwd:    rcwd},
					DestinationIp:   "127.0.0.1",
					DestinationPort: &wrappers.UInt32Value{Value: 8081},
				},
			},
		},
	}

	kprobe, err := getDefaultObserverWithWatchers(t, withPretty())
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}

	/* Verify initial KprobeEvent Execve "nc.traditional 127.0.0.1 8081 -e /bin/sh" */
	//	kprobe.AttachFilter(&ncExecFilter)
	/* Verify KprobeEvent TCPConnectReturn "nc.traditional 127.0.0.1 8081 -e /bin/sh" */
	//	kprobe.AttachFilter(&ncListen)
	//	kprobe.AttachFilter(&ncConnect)
	/* Verify KprobeEvent Execve '-e /bin/sh' without clone() */
	//	kprobe.AttachFilter(&ncExecCloneFilter)

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

	retries := jsonRetries
	if ok := jsonTestCompare(trace, nil, retries, 0); !ok {
		t.Fail()
	}
	testDone(t, kprobe)
}

func TestExistingListenEvent(t *testing.T) {
	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{Binary: selfBinary},
					Parent:  &fgs.Process{Binary: ""},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{
						Binary:    "nc.traditional",
						Arguments: "-nvlp 8081"},
					Parent: &fgs.Process{Binary: selfBinary},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessListen{
				ProcessListen: &fgs.ProcessListen{
					Process: &fgs.Process{
						Binary:    "nc.traditional",
						Arguments: "-nvlp 8081"},
					Parent: &fgs.Process{
						Binary: selfBinary},
					Ip:   "0.0.0.0",
					Port: &wrappers.UInt32Value{Value: 8081},
				},
			},
		},
	}

	/* Start server before creating kprobe */
	cmdServer := exec.Command("nc.traditional", "-nvlp", "8081")
	cmdServer.Start()

	/* Create kprobe */
	kprobe, err := getDefaultObserverWithWatchers(t)
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}

	if cmdServer != nil {
		cmdServer.Process.Kill()
	}

	retries := jsonRetries
	if ok := jsonTestCompare(trace, nil, retries, 0); !ok {
		t.Fail()
	}
	testDone(t, kprobe)
}

func TestExistingAcceptEvent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	rcwd := cwdPath(true)
	fcwd := cwdPath(false)

	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{Binary: selfBinary},
					Parent:  &fgs.Process{Binary: ""},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{
						Binary:    "nc.traditional",
						Arguments: "-nvlp 8081"},
					Parent: &fgs.Process{Binary: selfBinary},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessListen{
				ProcessListen: &fgs.ProcessListen{
					Process: &fgs.Process{
						Binary:    "nc.traditional",
						Arguments: "-nvlp 8081"},
					Parent: &fgs.Process{
						Binary: selfBinary},
					Ip:   "0.0.0.0",
					Port: &wrappers.UInt32Value{Value: 8081},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessAccept{
				ProcessAccept: &fgs.ProcessAccept{
					Process: &fgs.Process{
						Binary:    "nc.traditional",
						Arguments: "-nvlp 8081",
						Cwd:       fcwd},
					Parent: &fgs.Process{
						Binary: selfBinary,
						Cwd:    rcwd},
					SourceIp:   "127.0.0.1",
					SourcePort: &wrappers.UInt32Value{Value: 8081},
				},
			},
		},
	}

	/* Start server before creating kprobe */
	cmdServer := exec.Command("nc.traditional", "-nvlp", "8081")
	fmt.Printf("cmd: %s\n", cmdServer)
	cmdServer.Start()
	time.Sleep(1000 * time.Millisecond)

	/* Create kprobe */
	kprobe, err := getDefaultObserverWithWatchers(t)
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	loopEvents(t, &exitWG, &execWG, kprobe, ctx)

	execWG.Wait()
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command("nc.traditional", "127.0.0.1", "8081")
	fmt.Printf("cmd: %s\n", cmdClient)
	cmdClient.Start()
	exitWG.Wait()

	if cmdClient != nil {
		cmdClient.Process.Signal(syscall.SIGKILL)
	}
	if cmdServer != nil {
		cmdServer.Process.Signal(syscall.SIGKILL)
	}

	retries := jsonRetries
	if ok := jsonTestCompare(trace, nil, retries, 0); !ok {
		t.Fail()
	}
	testDone(t, kprobe)
}

func TestExistingRootCWDListenEvent(t *testing.T) {
	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{Binary: selfBinary},
					Parent:  &fgs.Process{Binary: ""},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{
						Binary:    "nc.traditional",
						Arguments: "-nvlp 8081"},
					Parent: &fgs.Process{Binary: selfBinary},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessListen{
				ProcessListen: &fgs.ProcessListen{
					Process: &fgs.Process{
						Binary:    "nc.traditional",
						Arguments: "-nvlp 8081"},
					Parent: &fgs.Process{
						Binary: selfBinary},
					Ip:   "0.0.0.0",
					Port: &wrappers.UInt32Value{Value: 8081},
				},
			},
		},
	}

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
	kprobe, err := getDefaultObserverWithWatchers(t)
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}

	if cmdServer != nil {
		cmdServer.Process.Kill()
	}
	retries := jsonRetries
	if ok := jsonTestCompare(trace, nil, retries, 0); !ok {
		t.Fail()
	}
	testDone(t, kprobe)
}

func TestLoadTCTls(t *testing.T) {
	if minKernelVersion("4.19.0") != true {
		return
	}
	kprobe, err := getDefaultObserverWithWatchers(t, withTLSTC())
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	testDone(t, kprobe)
}

func TestTCTls13(t *testing.T) {
	if minKernelVersion("4.19.0") != true {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{
						Binary:    "curl",
						Arguments: "https://google.com"},
					Parent: &fgs.Process{Binary: selfBinary},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessConnect{
				ProcessConnect: &fgs.ProcessConnect{
					Process: &fgs.Process{
						Binary:    "curl",
						Arguments: "https://google.com"},
					Parent: &fgs.Process{
						Binary: selfBinary},
					DestinationPort: &wrappers.UInt32Value{Value: 443},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_Tls{
				Tls: &fgs.Tls{
					Process: &fgs.Process{
						Binary:    "curl",
						Arguments: "https://google.com"},
					NegotiatedVersion: "TLS1.3",
					ClientVersion:     "TLS 1.2",
					ServerVersion:     "TLS 1.2",
					SniType:           "host_name",
					SniName:           "www.google.com",
					ClientFlags:       "ExtVersion",
					ServerFlags:       "ExtVersion",
				},
			},
		},
	}

	kprobe, err := getDefaultObserverWithWatchers(t, withTLSTC())
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWGCurl(&execWG, &exitWG, "https://google.com")
	retries := jsonRetries
	if ok := jsonTestCompare(trace, nil, retries, 0); !ok {
		t.Fail()
	}
	testDone(t, kprobe)
}

func TestTCTls12(t *testing.T) {
	if minKernelVersion("4.19.0") != true {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	certs := []string{
		"CN=*.badssl.com,O=Lucas Garron Torres,L=Walnut Creek,ST=California,C=US",
		"CN=DigiCert SHA2 Secure Server CA,O=DigiCert Inc,C=US",
	}

	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{
						Binary:    "curl",
						Arguments: "https://tls-v1-2.badssl.com:1012/"},
					Parent: &fgs.Process{Binary: selfBinary},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessConnect{
				ProcessConnect: &fgs.ProcessConnect{
					Process: &fgs.Process{
						Binary:    "curl",
						Arguments: "https://tls-v1-2.badssl.com:1012/"},
					Parent: &fgs.Process{
						Binary: selfBinary},
					DestinationPort: &wrappers.UInt32Value{Value: 1012},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_Tls{
				Tls: &fgs.Tls{
					Process: &fgs.Process{
						Binary:    "curl",
						Arguments: "https://tls-v1-2.badssl.com:1012/"},
					DestinationPort: &wrappers.UInt32Value{Value: 1012},
					ClientVersion:   "TLS 1.2",
					ServerVersion:   "TLS 1.2",
					SniType:         "host_name",
					SniName:         "tls-v1-2.badssl.com",
					ClientFlags:     "ExtVersion",
					ServerFlags:     "",
					Certificates:    certs,
				},
			},
		},
	}

	kprobe, err := getDefaultObserverWithWatchers(t, withTLSTC())
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWGCurl(&execWG, &exitWG, "https://tls-v1-2.badssl.com:1012/")
	retries := jsonRetries
	if ok := jsonTestCompare(trace, nil, retries, 0); !ok {
		t.Fail()
	}
	testDone(t, kprobe)
}

func TestListenAcceptClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	rcwd := cwdPath(true)
	fcwd := cwdPath(false)

	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{Binary: selfBinary},
					Parent:  &fgs.Process{Binary: ""},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{
						Binary:    "nc.traditional",
						Arguments: "-nvlp 8081",
						Cwd:       fcwd},
					Parent: &fgs.Process{Binary: selfBinary,
						Cwd: rcwd},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessListen{
				ProcessListen: &fgs.ProcessListen{
					Process: &fgs.Process{
						Binary:    "nc.traditional",
						Arguments: "-nvlp 8081",
						Cwd:       fcwd},
					Parent: &fgs.Process{
						Binary: selfBinary,
						Cwd:    rcwd},
					Ip:   "0.0.0.0",
					Port: &wrappers.UInt32Value{Value: 8081},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessAccept{
				ProcessAccept: &fgs.ProcessAccept{
					Process: &fgs.Process{
						Binary:    "nc.traditional",
						Arguments: "-nvlp 8081",
						Cwd:       fcwd},
					Parent: &fgs.Process{
						Binary: selfBinary,
						Cwd:    rcwd},
					SourceIp:   "127.0.0.1",
					SourcePort: &wrappers.UInt32Value{Value: 8081},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessClose{
				ProcessClose: &fgs.ProcessClose{
					Process: &fgs.Process{
						Binary:    "nc.traditional",
						Arguments: "-nvlp 8081",
						Cwd:       fcwd},
					Parent: &fgs.Process{
						Binary: selfBinary,
						Cwd:    rcwd},
					SourceIp:   "0.0.0.0",
					SourcePort: &wrappers.UInt32Value{Value: 8081},
				},
			},
		},
		/* I would also like to test this, but it goes into TIME_WAIT and then
		 * eventually close and I don't want to wait for it. So we need some
		 * go way to close the sockets.
		 */
		/*
			&fgs.GetEventsResponse{
				Event: &fgs.GetEventsResponse_ProcessClose{
					ProcessClose: &fgs.ProcessClose{
						Process: &fgs.Process{
							Binary:    "nc.traditional",
							Arguments: "-nvlp 8081",
							Cwd:       fcwd},
						Parent: &fgs.Process{
							Binary: selfBinary,
							Cwd:    rcwd},
						SourceIp:   "127.0.0.1",
						SourcePort: &wrappers.UInt32Value{Value: 8081},
					},
				},
			},
		*/
	}

	kprobe, err := getDefaultObserverWithWatchers(t, withPretty())
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	loopEvents(t, &exitWG, &execWG, kprobe, ctx)

	execWG.Wait()
	cmdServer := exec.Command("nc.traditional", "-nvlp", "8081")
	cmdServer.Start()
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command("nc.traditional", "127.0.0.1", "8081")
	cmdClient.Start()
	exitWG.Wait()

	if cmdClient != nil {
		cmdClient.Process.Signal(syscall.SIGKILL)
	}
	if cmdServer != nil {
		cmdServer.Process.Signal(syscall.SIGKILL)
	}
	retries := jsonRetries
	if ok := jsonTestCompare(trace, nil, retries, 0); !ok {
		t.Fail()
	}
	testDone(t, kprobe)
}

func TestSensorLseekLoad(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/debug/tracing/events/syscalls"); os.IsNotExist(err) {
		t.Skip("cannot use syscall tracepoints (consider enabling CONFIG_FTRACE_SYSCALLS)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_Test{},
		},
	}

	kprobe, err := getDefaultObserverWithWatchers(t)
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	progs := []*bpfLoad{&ObserverLseekTest}
	maps := []*ObserverMap{}
	sensor := &observerSensor{name: "lseekTest", progs: progs, maps: maps}
	if err := kprobe.observerLoadSensor(ctx, sensor); err != nil {
		kprobe.RemovePrograms()
		t.Fatalf("observerLoadSensor error: %s", err)
	}
	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWG.Wait()
	unix.Seek(-1, 0, 4444)
	exitWG.Wait()

	retries := jsonRetries
	if ok := jsonTestCompare(trace, nil, retries, 0); !ok {
		t.Fail()
	}

	kprobe.observerUnloadSensor(sensor, ctx)

	kprobe.RemovePrograms()
	kprobe.PrintStats()
}

func TestSensorLseekEnable(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/debug/tracing/events/syscalls"); os.IsNotExist(err) {
		t.Skip("cannot use syscall tracepoints (consider enabling CONFIG_FTRACE_SYSCALLS)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_Test{},
		},
	}

	kprobe, err := getDefaultObserverWithWatchers(t)
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	defer func() {
		kprobe.RemovePrograms()
		kprobe.PrintStats()
	}()

	sensorName := "lseekTest"
	progs := []*bpfLoad{&ObserverLseekTest}
	maps := []*ObserverMap{}
	sensor := &observerSensor{name: sensorName, progs: progs, maps: maps}
	registerSensor(sensor)

	if err := kprobe.startSensorCtl(); err != nil {
		t.Fatalf("startSensorController failed: %s", err)
	}
	defer func() {
		err := kprobe.stopSensorCtl(ctx)
		if err != nil {
			fmt.Printf("stopSensorController failed: %s\n", err)
		}
	}()

	if err := kprobe.EnableSensor(ctx, sensorName); err != nil {
		t.Fatalf("EnableSensor error: %s", err)
	}

	defer func() {
		err := kprobe.DisableSensor(ctx, sensorName)
		if err != nil {
			fmt.Printf("DisableSensor failed: %s\n", err)
		}
	}()

	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWG.Wait()
	unix.Seek(-1, 0, 4444)
	exitWG.Wait()

	retries := jsonRetries
	if ok := jsonTestCompare(trace, nil, retries, 0); !ok {
		t.Fail()
	}
}

// Create a fake Cilium state to avoid the events getting delayed due to missing pod info
func createFakeCiliumState(testPod, testNamespace string) *hubbleCilium.State {
	s := cilium.GetFakeCiliumState()
	s.GetEndpointsHandler().UpdateEndpoint(&hubbleV1.Endpoint{
		ID:           1234,
		PodName:      testPod,
		PodNamespace: testNamespace,
	})
	return s
}

// Create a fake K8s watcher to avoid delayed event due to missing pod info
func createFakeWatcher(testPod, testNamespace string) *fakeK8sWatcher {
	return &fakeK8sWatcher{
		OnFindPod: func(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool) {
			if containerID == "" {
				return nil, nil, false
			}

			container := corev1.ContainerStatus{
				Name:        containerID,
				Image:       "image",
				ImageID:     "id",
				ContainerID: "docker://" + containerID,
				State: corev1.ContainerState{
					Running: &corev1.ContainerStateRunning{
						StartedAt: v1.Time{
							Time: time.Unix(1, 2),
						},
					},
				},
			}
			pod := corev1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Name:      testPod,
					Namespace: testNamespace,
				},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						container,
					},
				},
			}

			return &pod, &container, true
		},
	}
}

func getDefaultObserverWithWatchers(t *testing.T, opts ...testOption) (*ObserverKprobe, error) {
	const (
		testPod       = "pod-1"
		testNamespace = "ns-1"
	)

	w := createFakeWatcher(testPod, testNamespace)
	s := createFakeCiliumState(testPod, testNamespace)

	opts = append(opts, withK8sWatcher(w))
	opts = append(opts, withCiliumState(s))
	return getDefaultObserver(t, opts...)
}

func TestDockerListenConnect(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker not available. skipping test: %s", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()
	var exitWG, execWG sync.WaitGroup
	var serverDockerID, clientDockerID string

	kprobe, err := getDefaultObserverWithWatchers(t, withPretty())
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
	}
	loopEvents(t, &exitWG, &execWG, kprobe, ctx)

	execWG.Wait()
	serverDockerID = dockerRun(t, "--name", "fgs-test-server", "--entrypoint", "nc", "quay.io/cilium/alpine-curl:1.0", "-nvlp", "8081")
	time.Sleep(1 * time.Second)
	clientDockerID = dockerRun(t, "--link", "fgs-test-server", "--entrypoint", "nc", "quay.io/cilium/alpine-curl:1.0", "fgs-test-server", "8081")
	exitWG.Wait()

	// FGS picks up the first 32 bytes
	fgsServerID := serverDockerID[:31]
	fgsClientID := clientDockerID[:31]

	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{Binary: selfBinary},
					Parent:  &fgs.Process{Binary: ""},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{
						Binary:    "/usr/bin/nc",
						Arguments: "-nvlp 8081",
						Cwd:       "/",
						Docker:    fgsServerID,
						Uid:       &wrappers.UInt32Value{Value: 0},
					},
					Parent: &fgs.Process{},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessListen{
				ProcessListen: &fgs.ProcessListen{
					Process: &fgs.Process{
						Binary:    "/usr/bin/nc",
						Arguments: "-nvlp 8081",
						Cwd:       "/",
						Docker:    fgsServerID,
						Uid:       &wrappers.UInt32Value{Value: 0},
					},
					Parent: &fgs.Process{},
					Ip:     "0.0.0.0",
					Port:   &wrappers.UInt32Value{Value: 8081},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{
						Binary:    "/usr/bin/nc",
						Arguments: "fgs-test-server 8081",
						Cwd:       "/",
						Docker:    fgsClientID,
						Uid:       &wrappers.UInt32Value{Value: 0},
					},
					Parent: &fgs.Process{},
				},
			},
		},

		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessConnect{
				ProcessConnect: &fgs.ProcessConnect{
					Process: &fgs.Process{
						Binary:    "/usr/bin/nc",
						Arguments: "fgs-test-server 8081",
						Cwd:       "/",
						Docker:    fgsClientID,
						Uid:       &wrappers.UInt32Value{Value: 0},
					},
					Parent:          &fgs.Process{},
					DestinationPort: &wrappers.UInt32Value{Value: 8081},
				},
			},
		},
	}

	retries := jsonRetries
	if ok := jsonTestCompare(trace, nil, retries, 0); !ok {
		t.Fail()
	}
	testDone(t, kprobe)
}

func Test_msgToExecveUnix(t *testing.T) {
	event := api.MsgExecveEvent{}

	// Minikube has "docker-" prefix.
	prefix := "docker-"
	minikubeID := prefix + "9e123a99b140a6ea4a8d15040ca2c8ee2d5ee9605e81d66ae4e3e29c3f0ef220.scope"
	copy(event.Kube.Docker[:], minikubeID)
	_, offset, err := procsDockerIdOffset(minikubeID)
	assert.NoError(t, err)
	result := msgToExecveUnix(&event, offset)
	assert.Equal(t, strings.Split(minikubeID, "-")[1][:api.DOCKER_ID_LENGTH-len(prefix)], result.Kube.Docker)
	event.Kube.Docker[0] = 0
	result = msgToExecveUnix(&event, offset)
	assert.Empty(t, result.Kube.Docker)

	// GKE doesn't.
	gkeID := "82836ef3675020258bee5075ace6264b3bc5300e20c975543cbc984bea59638f"
	copy(event.Kube.Docker[:], gkeID)
	result = msgToExecveUnix(&event, 0)
	assert.Equal(t, gkeID[:api.DOCKER_ID_LENGTH], result.Kube.Docker)
	event.Kube.Docker[0] = 0
	result = msgToExecveUnix(&event, offset)
	assert.Empty(t, result.Kube.Docker)
}

func TestDockerExistingListenEvent(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker not available. skipping test: %s", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()
	var exitWG, execWG sync.WaitGroup

	/* Start server before creating kprobe */
	dockerRun(t, "--name", "fgs-test-server", "--entrypoint", "nc", "quay.io/cilium/alpine-curl:1.0", "-nvlp", "8081")
	waitForProcess("nc -nvlp 8081")
	time.Sleep(2 * time.Second)

	/* Create kprobe */
	kprobe, err := getDefaultObserverWithWatchers(t, withPretty())
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	loopEvents(t, &exitWG, &execWG, kprobe, ctx)

	// Ideally we would also verify the dockerID, but our current dockerID
	// scanner from procFS does not match github actions docker env that
	// does not prepend a 'docker' string to the cgroup name. For now
	// drop the comparison and just ensure we get the events.
	//fgsServerID := serverDockerID[:31]

	// Current code reports binary behind symlink in proc case (binaries running
	// before fgs starts), but in runtime event we report the name of the symlink.
	// In this test the difference is busybox vs nc.
	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{Binary: selfBinary},
					Parent:  &fgs.Process{Binary: ""},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{
						Binary:    "/bin/busybox",
						Arguments: "-nvlp 8081",
						Cwd:       "/",
						Uid:       &wrappers.UInt32Value{Value: 0},
					},
					Parent: &fgs.Process{},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessListen{
				ProcessListen: &fgs.ProcessListen{
					Process: &fgs.Process{
						Binary:    "/bin/busybox",
						Arguments: "-nvlp 8081",
						Cwd:       "/",
						Uid:       &wrappers.UInt32Value{Value: 0},
					},
					Parent: &fgs.Process{},
					Ip:     "0.0.0.0",
					Port:   &wrappers.UInt32Value{Value: 8081},
				},
			},
		},
	}

	retries := jsonRetries
	if ok := jsonTestCompare(trace, nil, retries, 0); !ok {
		t.Fail()
	}
	testDone(t, kprobe)
}

func TestGenericTracepointSimple(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	lseekConf := GenericTracepointConf{
		Subsystem: "syscalls",
		Event:     "sys_enter_lseek",
		Args: []v1alpha1.TracepointArg{
			{Index: 7}, /* whence */
			{Index: 5}, /* fd */
		},
	}

	observer, err := getDefaultObserverWithWatchers(t, withTracepoint(lseekConf))
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
	}

	arg0 := &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_SizeArg{SizeArg: 4444}}
	arg1 := &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_SizeArg{SizeArg: 18446744073709551615}} // -1

	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessTracepoint{
				ProcessTracepoint: &fgs.ProcessTracepoint{
					Subsys: "syscalls",
					Event:  "sys_enter_lseek",
					Args:   []*fgs.KprobeArgument{arg0, arg1},
				},
			},
		},
	}

	loopEvents(t, &exitWG, &execWG, observer, ctx)
	execWG.Wait()
	unix.Seek(-1, 0, 4444)
	exitWG.Wait()
	retries := jsonRetries
	time.Sleep(1000 * time.Millisecond)
	if ok := jsonTestCompare(trace, nil, retries, 0); !ok {
		t.Fail()
	}
	testDone(t, observer)
}

func doTestGenericTracepointPidFilter(t *testing.T, conf GenericTracepointConf, selfOp func(), checkFn func(*fgs.ProcessTracepoint) error) {
	defer func() {
		if t.Failed() {
			if fname, err := jsonTestSaveCopy(nil); err != nil {
				t.Logf("Failed to save a copy of json out: %s", err)
			} else {
				t.Logf("Saved a copy of json out: %s", fname)
			}
		}
	}()

	if _, err := os.Stat("/sys/kernel/debug/tracing/events/syscalls"); os.IsNotExist(err) {
		t.Skip("cannot use syscall tracepoints (consider enabling CONFIG_FTRACE_SYSCALLS)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5000*time.Millisecond)
	defer cancel()

	pid := int(getMyPid())
	t.Logf("filtering for my pid (%d)", pid)
	pidFilter := v1alpha1.PIDFilter{
		Op:             "eq",
		IsNamespacePID: false,
		FollowForks:    true,
		Value:          uint32(pid),
	}

	conf.Filters.PIDs = append(conf.Filters.PIDs, pidFilter)
	observer, err := getDefaultObserverWithWatchers(t, withTracepoint(conf))
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
	}

	var exitWG, execWG sync.WaitGroup
	loopEvents(t, &exitWG, &execWG, observer, ctx)
	execWG.Wait()
	selfOp()
	exitWG.Wait()

	tpEventsNr := 0
	checkEventFn := func(event *fgs.GetEventsResponse) error {
		switch tpEvent := event.Event.(type) {
		case *fgs.GetEventsResponse_ProcessTracepoint:
			if err := checkFn(tpEvent.ProcessTracepoint); err != nil {
				return err
			}
			eventPid := tpEvent.ProcessTracepoint.Process.Pid.Value
			if int(eventPid) != pid {
				return fmt.Errorf("Unexpected pid=%d (filter is for pid %d)", eventPid, pid)
			}
			tpEventsNr += 1
		default:
			return nil

		}
		return nil
	}

	if err := jsonTestIterate(nil, checkEventFn); err != nil {
		t.Logf("error: %s", err)
		t.Fail()
	}

	// NB: in some cases we get more events. I think this
	// might be to -EINTR or similar. Will need to include the return value
	// to do proper testing.
	if tpEventsNr < 1 {
		t.Logf("Got %d events while expecting at least 1", tpEventsNr)
		t.Fail()
	}

	testDone(t, observer)
}

func TestGenericTracepointPidFilterLseek(t *testing.T) {
	tracepointConf := GenericTracepointConf{
		Subsystem: "syscalls",
		Event:     "sys_enter_lseek",
	}

	op := func() {
		fmt.Printf("Calling lseek...\n")
		unix.Seek(-1, 0, 4444)
	}

	check := func(event *fgs.ProcessTracepoint) error {
		return nil
	}

	doTestGenericTracepointPidFilter(t, tracepointConf, op, check)
}

func TestGenericTracepointArgFilterLseek(t *testing.T) {
	fd_u := uint64(100)
	fd := 100
	whence_u := uint64(4444)
	whence := 4444

	tracepointConf := GenericTracepointConf{
		Subsystem: "syscalls",
		Event:     "sys_enter_lseek",
		Args: []v1alpha1.TracepointArg{
			v1alpha1.TracepointArg{
				Index: 7, /* whence */
			},
			v1alpha1.TracepointArg{
				Index: 5, /* fd */
			},
		},
		Filters: v1alpha1.TracepointFilters{
			Args: []v1alpha1.ArgFilter{{
				Index: 7,
				Op:    "eq",
				Value: strconv.Itoa(whence),
			}},
		},
	}

	op := func() {
		fmt.Printf("Calling lseek...\n")
		unix.Seek(fd, 0, whence)
		unix.Seek(fd, 0, whence+1)
	}

	check := func(event *fgs.ProcessTracepoint) error {
		if len(event.Args) != 2 {
			return fmt.Errorf("unexpected number of arguments: %d", len(event.Args))
		}
		arg0, ok := event.Args[0].GetArg().(*fgs.KprobeArgument_SizeArg)
		if !ok {
			return fmt.Errorf("unexpected first arg: %s", event.Args[0])
		}
		xwhence := arg0.SizeArg
		if xwhence != whence_u {
			return fmt.Errorf("unexpected arg val. got:%d expecting:%d", xwhence, whence)
		}
		arg1, ok := event.Args[1].GetArg().(*fgs.KprobeArgument_SizeArg)
		if !ok {
			return fmt.Errorf("unexpected first arg: %s", event.Args[1])
		}
		xfd := arg1.SizeArg
		if xfd != fd_u {
			return fmt.Errorf("unexpected arg val. got:%d expecting:%d", xfd, fd)
		}
		return nil
	}

	doTestGenericTracepointPidFilter(t, tracepointConf, op, check)

}

func TestGenericTracepointMeta(t *testing.T) {
	tracepointConf := GenericTracepointConf{
		Subsystem: "syscalls",
		Event:     "sys_enter_write",
		Args: []v1alpha1.TracepointArg{
			v1alpha1.TracepointArg{
				Index: 5, /* fd */
			},
			v1alpha1.TracepointArg{
				Index:        6,     /* char *buf */
				SizeArgIndex: 7 + 1, /* count */

			},
		},
		Filters: v1alpha1.TracepointFilters{
			Args: []v1alpha1.ArgFilter{{
				Index: 5,
				Op:    "eq",
				Value: "1",
			}},
		},
	}

	op := func() {
		syscall.Write(1, []byte("hello world"))
	}

	found := false
	check := func(event *fgs.ProcessTracepoint) error {
		if event.Subsys != "syscalls" {
			return fmt.Errorf("Unexpected subsys: %s", event.Subsys)
		}
		if event.Event != "sys_enter_write" {
			return fmt.Errorf("Unexpected subsys: %s", event.Event)
		}
		if len(event.Args) != 2 {
			return fmt.Errorf("Expecting single argument, but got %d", len(event.Args))
		}
		arg1_, ok := event.Args[1].GetArg().(*fgs.KprobeArgument_StringArg)
		if !ok {
			return fmt.Errorf("Unexpected arg: %v", event.Args[1].GetArg())
		}
		arg1 := arg1_.StringArg
		if arg1 == "hello world" {
			found = true
		}
		return nil
	}

	doTestGenericTracepointPidFilter(t, tracepointConf, op, check)
	if !found {
		t.Logf("expected string not found")
		t.Fail()
	}
}
