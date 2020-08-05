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

func getDefaultObserver(t *testing.T, execve, tls, tlstc, pretty bool) *ObserverKprobe {
	var uts syscall.Utsname

	if err := syscall.Uname(&uts); err != nil {
		t.Fatalf("sys.Uname error: %s", err)
	}

	buf := make([]byte, 65)
	for i, b := range uts.Release {
		buf[i] = byte(b)
	}
	ObserverExecve.Observer__program = "../../bpf/objs/bpf_execve_event.o"
	ObserverFork.Observer__program = "../../bpf/objs/bpf_fork.o"
	ObserverTCPConnect.Observer__program = "../../bpf/objs/bpf_tcpmon.o"
	ObserverTCPConnectRet.Observer__program = "../../bpf/objs/bpf_tcpmonret.o"
	ObserverListen.Observer__program = "../../bpf/objs/bpf_listen.o"
	ObserverSockopsEstablished.Observer__program = "../../bpf/objs/bpf_sockops.o"
	ObserverSkmsgTLS.Observer__program = "../../bpf/objs/bpf_skmsg_tls.o"
	ObserverCgrpIngress.Observer__program = "../../bpf/objs/bpf_cgrp_in_tls.o"
	ObserverTLSEvent.Observer__program = "../../bpf/objs/bpf_event_tls.o"
	ObserverTLSTCIngress.Observer__program = "../../bpf/objs/bpf_tc_ingress.o"
	ObserverTLSTCEgress.Observer__program = "../../bpf/objs/bpf_tc_egress.o"

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

	kprobe := NewObserverKprobe(observerTestDir, observerTestDir, "", execve, tls, tlstc, pretty)
	if testing.Verbose() {
		Verbosity = 0
	}
	loadExporter(t, kprobe)
	loadObserver(t, kprobe)

	kprobe.perfConfig = bpf.DefaultPerfEventConfig()
	kprobe.perfConfig.MapName = observerTestDir + "tcpmon_map"
	return kprobe
}

func loadExporter(t *testing.T, kprobe *ObserverKprobe) error {
	ctx, _ := context.WithCancel(context.Background())

	os.Remove(exportFile)

	watcher := fgsGrpc.NewFakeK8sWatcher(nil)
	ciliumState := cilium.GetFakeCiliumState()
	processCacheSize := 32768
	processManager, err := fgsGrpc.NewProcessManager(logger.GetLogger(), processCacheSize, watcher, ciliumState)
	if err != nil {
		return err
	}
	server := fgsGrpc.NewServer(processManager)
	writer := lumberjack.Logger{
		Filename:   exportFile,
		MaxSize:    10,
		MaxBackups: 1,
		Compress:   false,
	}
	encoder := json.NewEncoder(&writer)

	f := fmt.Sprintf(`{"pid_set":[%d]}`, getMyPid())
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
	if err := kprobe.observerLoadExecve(context.TODO()); err != nil {
		kprobe.RemovePrograms()
		t.Fatalf("observerLoadExecve error: %s", err)
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
	kprobe := getDefaultObserver(t, false, false, false, false)
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
		fmt.Printf("compareProcess: expected binary %s found binary %s\n",
			b.Binary, a.Binary)
		return false
	}
	if b.Arguments != "" && strings.Contains(a.Arguments, b.Arguments) == false {
		fmt.Printf("compareProcess (%s): expected binary %s found binary %s\n",
			a.Binary, b.Arguments, a.Arguments)
		return false
	}
	if b.Cwd != "" && strings.Contains(a.Cwd, b.Cwd) == false {
		fmt.Printf("compareProcess (%s): expected Cwd %s found Cwd %s\n",
			a.Binary, b.Cwd, a.Cwd)
		return false
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

func jsonTestCompare(trace []*fgs.GetEventsResponse) bool {
	ev := fgs.GetEventsResponse{}
	jsonFile, err := os.Open(exportFile)
	if err != nil {
		return false
	}
	defer jsonFile.Close()

	dec := json.NewDecoder(jsonFile)
	for _, t := range trace {
		err = jsonpb.UnmarshalNext(dec, &ev)
		if err != nil {
			return false
		}
		switch res := ev.Event.(type) {
		case *fgs.GetEventsResponse_ProcessConnect:
			fmt.Printf("process_connect\n")
			switch bRes := t.Event.(type) {
			case *fgs.GetEventsResponse_ProcessConnect:
				if ok := jsonTestCompareConnect(res, bRes); !ok {
					return false
				}
			default:
				return false
			}
		case *fgs.GetEventsResponse_ProcessExec:
			fmt.Printf("process_exec\n")
			switch bRes := t.Event.(type) {
			case *fgs.GetEventsResponse_ProcessExec:
				if ok := jsonTestCompareExecve(res, bRes); !ok {
					return false
				}
			default:
				return false
			}
		case *fgs.GetEventsResponse_ProcessListen:
			fmt.Printf("process_listen\n")
			switch bRes := t.Event.(type) {
			case *fgs.GetEventsResponse_ProcessListen:
				if ok := jsonTestCompareListen(res, bRes); !ok {
					return false
				}
			default:
				return false
			}

		case *fgs.GetEventsResponse_Tls:
			fmt.Printf("process_tls\n")
		default:
			fmt.Printf("unknown\n")
		}
	}

	return true
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

	kprobe := getDefaultObserver(t, true, false, false, true)

	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWGCurl(&execWG, &exitWG, "127.0.0.1")
	if ok := jsonTestCompare(trace); !ok {
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

	kprobe := getDefaultObserver(t, true, false, false, true)

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

	if ok := jsonTestCompare(trace); !ok {
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
	kprobe := getDefaultObserver(t, true, false, false, false)

	if cmdServer != nil {
		cmdServer.Process.Kill()
	}

	if ok := jsonTestCompare(trace); !ok {
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
	kprobe := getDefaultObserver(t, true, false, false, false)
	if cmdServer != nil {
		cmdServer.Process.Kill()
	}
	if ok := jsonTestCompare(trace); !ok {
		t.Fail()
	}
	testDone(t, kprobe)
}

func TestLoadTCTls(t *testing.T) {
	if minKernelVersion("4.19.0") != true {
		return
	}
	getDefaultObserver(t, true, false, true, false)
}
