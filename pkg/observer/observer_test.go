package observer

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
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

	"github.com/covalentio/hubble-fgs/api/v1/fgs"
	"github.com/covalentio/hubble-fgs/pkg/bpf"
	"github.com/covalentio/hubble-fgs/pkg/cilium"
	"github.com/covalentio/hubble-fgs/pkg/filters"
	fgsGrpc "github.com/covalentio/hubble-fgs/pkg/grpc"
	"github.com/covalentio/hubble-fgs/pkg/logger"
	"github.com/covalentio/hubble-fgs/pkg/mountinfo"
	"github.com/covalentio/hubble-fgs/pkg/reader"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/ptypes/wrappers"

	"gopkg.in/natefinch/lumberjack.v2"

	"golang.org/x/sys/unix"
)

var (
	observerTestDir = "/sys/fs/bpf/testObserver/"
	exportFile      = "/tmp/hubble-fgs.gotest"
	jsonRetries     = 4
	retryDelay      = 2 * time.Second
)

func minKernelVersion(kernel string) bool {
	var uname unix.Utsname

	if err := unix.Uname(&uname); err != nil {
		return true
	}
	//n := bytes.IndexByte(uname.Release[:], 0)
	// vendors like to define kernel 4.14.128-foo but
	// everything after '-' is meaningless from BPF
	// side so toss it out.
	release := strings.Split(string(uname.Release[:]), "-")
	numeric := strings.TrimRight(release[0], "+")
	runningVersion := int(kernelStringToNumeric(numeric))
	minVersion := int(kernelStringToNumeric(kernel))
	if minVersion <= runningVersion {
		return true
	}
	return false
}

func TestMain(m *testing.M) {
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.ConfigureResourceLimits()
	exitCode := m.Run()
	os.Exit(exitCode)
}

func getDefaultObserver(t *testing.T, tls, tlstc, pretty bool) (*ObserverKprobe, error) {
	ctx, _ := context.WithCancel(context.Background())
	var uts syscall.Utsname

	if err := syscall.Uname(&uts); err != nil {
		t.Fatalf("sys.Uname error: %s", err)
	}

	buf := make([]byte, 65)
	for i, b := range uts.Release {
		buf[i] = byte(b)
	}
	ObserverExecve.Observer__program = "../../bpf/objs/bpf_execve_event.o"
	ObserverExit.Observer__program = "../../bpf/objs/bpf_exit.o"
	ObserverFork.Observer__program = "../../bpf/objs/bpf_fork.o"
	ObserverTCPConnect.Observer__program = "../../bpf/objs/bpf_tcpmon.o"
	ObserverTCPConnectRet.Observer__program = "../../bpf/objs/bpf_tcpmonret.o"
	ObserverTCPClose.Observer__program = "../../bpf/objs/bpf_tcpclose.o"
	ObserverListen.Observer__program = "../../bpf/objs/bpf_listen.o"
	ObserverSockopsEstablished.Observer__program = "../../bpf/objs/bpf_sockops.o"
	ObserverSkmsg.Observer__program = "../../bpf/objs/bpf_skmsg.o"
	ObserverTLSTCIngress.Observer__program = "../../bpf/objs/bpf_tc_ingress.o"
	ObserverTLSTCEgress.Observer__program = "../../bpf/objs/bpf_tc_egress.o"
	ObserverLseekTest.Observer__program = "../../bpf/objs/bpf_lseek.o"
	ObserverCred.Observer__program = "../../bpf/objs/bpf_cred.o"

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

	kprobe := NewObserverKprobe(observerTestDir, observerTestDir, "", "", tls, tlstc, pretty)
	if testing.Verbose() {
		Verbosity = 1
	}
	err := kprobe.ConfigureBTF(ctx)
	if err != nil {
		return nil, err
	}

	loadExporter(t, kprobe)
	loadObserver(t, kprobe)

	kprobe.perfConfig = bpf.DefaultPerfEventConfig()
	kprobe.perfConfig.MapName = observerTestDir + "tcpmon_map"
	return kprobe, nil
}

func loadExporter(t *testing.T, kprobe *ObserverKprobe) error {
	ctx, _ := context.WithCancel(context.Background())

	os.Remove(exportFile)

	watcher := fgsGrpc.NewFakeK8sWatcher(nil)
	ciliumState := cilium.GetFakeCiliumState()
	processCacheSize := 32768
	processManager, err := fgsGrpc.NewProcessManager(logger.GetLogger(), processCacheSize, watcher, ciliumState, true, true)
	if err != nil {
		return err
	}
	server := fgsGrpc.NewServer(processManager, kprobe)
	writer := lumberjack.Logger{
		Filename:   exportFile,
		MaxSize:    10,
		MaxBackups: 1,
		Compress:   false,
	}
	encoder := json.NewEncoder(&writer)

	// temporarily disable the allow list while we fixup TLS events
	// to include parent reference as well
	f := "" //fmt.Sprintf(`{"pid_set":[%d]}`, getMyPid())
	allowList, err := filters.ParseFilterList(f)
	if err != nil {
		t.Fatalf("observerLoadExporter: %s\n", err)
	}
	denyList, _ := filters.ParseFilterList("")
	req := fgs.GetEventsRequest{AllowList: allowList, DenyList: denyList}
	exporter := fgsGrpc.NewExporter(ctx, &req, server, encoder)
	go exporter.Start()
	kprobe.AddListener(processManager)
	return nil
}

func loadObserver(t *testing.T, kprobe *ObserverKprobe) {
	kprobe.createDir()
	initialSensor := kprobe.createInitialObserverSensor()
	if err := kprobe.observerLoadSensor(context.TODO(), initialSensor); err != nil {
		kprobe.RemovePrograms()
		t.Fatalf("observerLoadProgs error: %s", err)
	}
	kprobe.populateExecve(context.TODO())
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
	kprobe, err := getDefaultObserver(t, false, false, false)
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
	}
	initialSensor := kprobe.createInitialObserverSensor()
	kprobe.observerLoadSensor(context.TODO(), initialSensor)
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
		path = path[:len(path)-1]
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

func compareProcess(a, b *fgs.Process) bool {
	if b.Pid != nil && b.Pid.Value != 0 && a.Pid.Value != b.Pid.Value {
		fmt.Printf("compareProcess (%s): expected pid %d found pid %d\n",
			a.Binary, b.Pid.Value, a.Pid.Value)
		return false
	}
	if b.Binary != "" && strings.Contains(a.Binary, b.Binary) == false {
		return false
	}
	if b.Arguments != "" && strings.Contains(a.Arguments, b.Arguments) == false {
		return false
	}
	if b.Cwd != "" && strings.Contains(a.Cwd, b.Cwd) == false {
		fmt.Printf("compareProcess (%s): expected Cwd %s found Cwd %s\n",
			a.Binary, b.Cwd, a.Cwd)
		//return false
	}
	return true
}

func jsonTestCompareExecve(a, b *fgs.GetEventsResponse_ProcessExec) bool {
	aExecve := a.ProcessExec
	bExecve := b.ProcessExec

	if ok := compareProcess(aExecve.Process, bExecve.Process); !ok {
		return false
	}
	if ok := compareProcess(aExecve.Parent, bExecve.Parent); !ok {
		return false
	}
	return true
}

func jsonTestCompareConnect(a, b *fgs.GetEventsResponse_ProcessConnect) bool {
	aConnect := a.ProcessConnect
	bConnect := b.ProcessConnect

	if ok := compareProcess(aConnect.Process, bConnect.Process); !ok {
		return false
	}
	if ok := compareProcess(aConnect.Parent, bConnect.Parent); !ok {
		return false
	}
	if bConnect.DestinationIp != "" && bConnect.DestinationIp != aConnect.DestinationIp {
		fmt.Printf("compareConnect (%s): expected destIP %s found destIp %s\n",
			aConnect.Process.Binary, bConnect.DestinationIp, aConnect.DestinationIp)
		return false
	}
	if bConnect.SourceIp != "" && bConnect.SourceIp != aConnect.SourceIp {
		fmt.Printf("compareConnect (%s): expected sourceIP %s found sourceIp %s\n",
			aConnect.Process.Binary, bConnect.SourceIp, aConnect.SourceIp)
		return false
	}
	if bConnect.DestinationPort != nil &&
		bConnect.DestinationPort.Value != 0 &&
		aConnect.DestinationPort.Value != bConnect.DestinationPort.Value {
		fmt.Printf("compareConnect (%s): expect source port %d found source port %d",
			aConnect.Process.Binary, bConnect.DestinationPort.Value, aConnect.DestinationPort.Value)
		return false
	}
	if bConnect.SourcePort != nil &&
		bConnect.SourcePort.Value != 0 &&
		aConnect.SourcePort.Value != bConnect.SourcePort.Value {
		fmt.Printf("compareConnec (%s): expect source port %d found source port %d",
			aConnect.Process.Binary, bConnect.SourcePort.Value, aConnect.SourcePort.Value)
		return false
	}
	return true
}

func jsonTestCompareListen(a, b *fgs.GetEventsResponse_ProcessListen) bool {
	aListen := a.ProcessListen
	bListen := b.ProcessListen

	if ok := compareProcess(aListen.Process, bListen.Process); !ok {
		return false
	}
	if ok := compareProcess(aListen.Parent, bListen.Parent); !ok {
		return false
	}
	if bListen.Ip != "" && bListen.Ip != aListen.Ip {
		fmt.Printf("compareListen: expected IP %s found Ip %s\n",
			bListen.Ip, aListen.Ip)
		return false
	}
	if bListen.Port != nil &&
		bListen.Port.Value != 0 &&
		aListen.Port.Value != bListen.Port.Value {
		fmt.Printf("compareListen: expect port %d found port %d",
			bListen.Port.Value, aListen.Port.Value)
		return false
	}
	return true
}

func jsonTestCompareAccept(a, b *fgs.GetEventsResponse_ProcessAccept) bool {
	aAccept := a.ProcessAccept
	bAccept := b.ProcessAccept

	if ok := compareProcess(aAccept.Process, bAccept.Process); !ok {
		return false
	}
	if ok := compareProcess(aAccept.Parent, bAccept.Parent); !ok {
		return false
	}
	if bAccept.SourceIp != "" && bAccept.SourceIp != aAccept.SourceIp {
		fmt.Printf("compareListen: expected IP %s found Ip %s\n",
			bAccept.SourceIp, aAccept.SourceIp)
		return false
	}
	if bAccept.SourcePort != nil &&
		bAccept.SourcePort.Value != 0 &&
		aAccept.SourcePort.Value != bAccept.SourcePort.Value {
		fmt.Printf("compareListen: expect port %d found port %d",
			bAccept.SourcePort.Value, aAccept.SourcePort.Value)
		return false
	}
	return true
}

func jsonTestCompareClose(a, b *fgs.GetEventsResponse_ProcessClose) bool {
	aClose := a.ProcessClose
	bClose := b.ProcessClose

	if ok := compareProcess(aClose.Process, bClose.Process); !ok {
		return false
	}
	if ok := compareProcess(aClose.Parent, bClose.Parent); !ok {
		return false
	}
	if bClose.SourceIp != "" && bClose.SourceIp != aClose.SourceIp {
		fmt.Printf("compareClose: expected IP %s found Ip %s\n",
			bClose.SourceIp, aClose.SourceIp)
		return false
	}
	if bClose.SourcePort != nil &&
		bClose.SourcePort.Value != 0 &&
		aClose.SourcePort.Value != bClose.SourcePort.Value {
		fmt.Printf("compareClose: expect port %d found port %d",
			bClose.SourcePort.Value, aClose.SourcePort.Value)
		return false
	}
	if bClose.DestinationIp != "" && bClose.DestinationIp != aClose.DestinationIp {
		fmt.Printf("compareClose: expected IP %s found Ip %s\n",
			bClose.DestinationIp, aClose.DestinationIp)
		return false
	}
	if bClose.DestinationPort != nil &&
		bClose.DestinationPort.Value != 0 &&
		aClose.DestinationPort.Value != bClose.DestinationPort.Value {
		fmt.Printf("compareClose: expect port %d found port %d",
			bClose.DestinationPort.Value, aClose.DestinationPort.Value)
		return false
	}
	return true
}
func jsonTestCompareTls(a, b *fgs.GetEventsResponse_Tls) bool {
	aTls := a.Tls
	bTls := b.Tls

	if ok := compareProcess(aTls.Process, bTls.Process); !ok {
		return false
	}
	if bTls.NegotiatedVersion != "" && bTls.NegotiatedVersion != aTls.NegotiatedVersion {
		fmt.Printf("compareTls: expected NegotiatedVersion %s found NegotiatedVersion %s\n",
			bTls.NegotiatedVersion, aTls.NegotiatedVersion)
		return false
	}
	if bTls.SupportedVersions != "" && bTls.SupportedVersions != aTls.SupportedVersions {
		fmt.Printf("compareTls: expected SupportedVersion %s found SupportedVersion %s\n",
			bTls.SupportedVersions, aTls.SupportedVersions)
		return false
	}
	if bTls.ClientVersion != "" && bTls.ClientVersion != a.Tls.ClientVersion {
		fmt.Printf("compareTls: expect ClientVersion %s found ClientVersion %s",
			bTls.ClientVersion, aTls.ClientVersion)
		return false
	}
	if bTls.SniName != "" && strings.Contains(bTls.SniName, aTls.SniName) == false {
		fmt.Printf("compareTls: expected SniName %s found SniName %s",
			bTls.SniName, bTls.SniName)
		return false
	}
	if bTls.SniType != "" && bTls.SniType != aTls.SniType {
		fmt.Printf("compareTls: expected SniType %s found SniType %s",
			bTls.SniType, bTls.SniType)
		return false
	}

	if bTls.ClientFlags != aTls.ClientFlags {
		fmt.Printf("compareTls: expected ClientFlags %s found ClientFlags %s",
			bTls.ClientFlags, bTls.ClientFlags)
		return false
	}

	if bTls.ServerFlags != aTls.ServerFlags {
		fmt.Printf("compareTls: expected ServerFlags %s found ServerFlags %s",
			bTls.ServerFlags, bTls.ServerFlags)
		return false
	}

	return true
}

func eventTypeString(ev interface{}) string {
	switch ev.(type) {
	case *fgs.GetEventsResponse_ProcessConnect:
		return "ProcessConnect"
	case *fgs.GetEventsResponse_ProcessListen:
		return "ProcessListen"
	case *fgs.GetEventsResponse_ProcessAccept:
		return "ProcessAccept"
	case *fgs.GetEventsResponse_Tls:
		return "Tls"
	case *fgs.GetEventsResponse_ProcessExec:
		return "ProcessExec"
	case *fgs.GetEventsResponse_ProcessExit:
		return "ProcessExit"
	case *fgs.GetEventsResponse_ProcessClose:
		return "ProcessClose"
	case *fgs.GetEventsResponse_Test:
		return "Test"
	default:
		return fmt.Sprintf("<UNKNOWN:%T>", ev)
	}
}

func verbosePrintf(s string) {
	if Verbosity > 0 {
		fmt.Printf(s)
	}
}

func jsonTestCompare(trace []*fgs.GetEventsResponse, jsonFile *os.File, attempts, found int) bool {
	var err error

	if attempts < 1 {
		return false
	}

	ev := fgs.GetEventsResponse{}
	if jsonFile == nil {
		fmt.Printf("jsonTestCompare: openning: %s\n", exportFile)
		jsonFile, err = os.Open(exportFile)
		if err != nil {
			return false
		}
		defer jsonFile.Close()
	}

	dec := json.NewDecoder(jsonFile)
	for tidx, t := range trace[found:] {
		for {
			err = jsonpb.UnmarshalNext(dec, &ev)
			if err != nil {
				goto retry
			}

			evTyStr := eventTypeString(ev.Event)
			trTyStr := eventTypeString(t.Event)
			if Verbosity > 0 {
				fmt.Printf("tidx=%d found=%d => got %s looking for %s (string match:%t)\n", tidx, found, evTyStr, trTyStr, evTyStr == trTyStr)
			}
			switch res := ev.Event.(type) {
			case *fgs.GetEventsResponse_ProcessConnect:
				switch bRes := t.Event.(type) {
				case *fgs.GetEventsResponse_ProcessConnect:
					if ok := jsonTestCompareConnect(res, bRes); ok {
						found++
						verbosePrintf("\tFOUND IT!\n")
						goto next
					}
				}
			case *fgs.GetEventsResponse_ProcessExec:
				switch bRes := t.Event.(type) {
				case *fgs.GetEventsResponse_ProcessExec:
					if ok := jsonTestCompareExecve(res, bRes); ok {
						found++
						verbosePrintf("\tFOUND IT!\n")
						goto next
					}
				}
			case *fgs.GetEventsResponse_ProcessListen:
				switch bRes := t.Event.(type) {
				case *fgs.GetEventsResponse_ProcessListen:
					if ok := jsonTestCompareListen(res, bRes); ok {
						found++
						verbosePrintf("\tFOUND IT!\n")
						goto next
					}
				}
			case *fgs.GetEventsResponse_ProcessAccept:
				switch bRes := t.Event.(type) {
				case *fgs.GetEventsResponse_ProcessAccept:
					if ok := jsonTestCompareAccept(res, bRes); ok {
						found++
						verbosePrintf("\tFOUND IT!\n")
						goto next
					}
				}
			case *fgs.GetEventsResponse_Tls:
				switch bRes := t.Event.(type) {
				case *fgs.GetEventsResponse_Tls:
					if ok := jsonTestCompareTls(res, bRes); ok {
						found++
						verbosePrintf("\tFOUND IT!\n")
						goto next
					}
				}
			case *fgs.GetEventsResponse_ProcessExit:
			case *fgs.GetEventsResponse_ProcessClose:
				switch bRes := t.Event.(type) {
				case *fgs.GetEventsResponse_ProcessClose:
					if ok := jsonTestCompareClose(res, bRes); ok {
						found++
						verbosePrintf("\tFOUND IT!\n")
						goto next
					}
				}

			case *fgs.GetEventsResponse_Test:
				switch t.Event.(type) {
				case *fgs.GetEventsResponse_Test:
					found++
					verbosePrintf("\tFOUND IT!\n")
					goto next
				}

			default:
				verbosePrintf("unknown\n")
			}
		}
	next:
	}

	if found == len(trace) {
		verbosePrintf("\tFOUND ALL!\n")
		return true
	}
retry:
	attempts--
	time.Sleep(retryDelay)
	return jsonTestCompare(trace, jsonFile, attempts, found)
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

	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{Binary: "go-build"},
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
					Parent: &fgs.Process{Binary: "go-build"},
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
						Binary: "go-build"},
					DestinationIp:   "127.0.0.1",
					DestinationPort: &wrappers.UInt32Value{Value: 80},
				},
			},
		},
	}

	kprobe, err := getDefaultObserver(t, false, false, true)
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
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
	ctx, cancel := context.WithTimeout(context.Background(), 10000*time.Millisecond)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	rcwd := cwdPath(true)
	fcwd := cwdPath(false)

	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{Binary: "go-build"},
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
					Parent: &fgs.Process{Binary: "go-build",
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
						Binary: "go-build",
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
						Binary: "go-build",
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
						Binary: "go-build",
						Cwd:    rcwd},
					DestinationIp:   "127.0.0.1",
					DestinationPort: &wrappers.UInt32Value{Value: 8081},
				},
			},
		},
	}

	kprobe, err := getDefaultObserver(t, false, false, true)
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
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
					Process: &fgs.Process{Binary: "go-build"},
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
					Parent: &fgs.Process{Binary: "go-build"},
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
						Binary: "go-build"},
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
	kprobe, err := getDefaultObserver(t, false, false, false)
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
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

func TestExistingRootCWDListenEvent(t *testing.T) {
	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{Binary: "go-build"},
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
					Parent: &fgs.Process{Binary: "go-build"},
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
						Binary: "go-build"},
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
	kprobe, err := getDefaultObserver(t, false, false, false)
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
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
	kprobe, err := getDefaultObserver(t, false, true, false)
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
	}
	testDone(t, kprobe)
}

func TestTCTls13(t *testing.T) {
	if minKernelVersion("4.19.0") != true {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10000*time.Millisecond)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{
						Binary:    "curl",
						Arguments: "https://google.com"},
					Parent: &fgs.Process{Binary: "go-build"},
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
						Binary: "go-build"},
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

	kprobe, err := getDefaultObserver(t, false, true, false)
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
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

	ctx, cancel := context.WithTimeout(context.Background(), 10000*time.Millisecond)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{
						Binary:    "curl",
						Arguments: "https://tls-v1-2.badssl.com:1012/"},
					Parent: &fgs.Process{Binary: "go-build"},
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
						Binary: "go-build"},
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
				},
			},
		},
	}

	kprobe, err := getDefaultObserver(t, false, true, false)
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
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
	ctx, cancel := context.WithTimeout(context.Background(), 10000*time.Millisecond)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	rcwd := cwdPath(true)
	fcwd := cwdPath(false)

	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{Binary: "go-build"},
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
					Parent: &fgs.Process{Binary: "go-build",
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
						Binary: "go-build",
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
						Binary: "go-build",
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
						Binary: "go-build",
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
							Binary: "go-build",
							Cwd:    rcwd},
						SourceIp:   "127.0.0.1",
						SourcePort: &wrappers.UInt32Value{Value: 8081},
					},
				},
			},
		*/
	}

	kprobe, err := getDefaultObserver(t, false, false, true)
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
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
	ctx, cancel := context.WithTimeout(context.Background(), 10000*time.Millisecond)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_Test{},
		},
	}

	kprobe, err := getDefaultObserver(t, false, false, false)
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
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
	ctx, cancel := context.WithTimeout(context.Background(), 10000*time.Millisecond)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_Test{},
		},
	}

	kprobe, err := getDefaultObserver(t, false, false, false)
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
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
