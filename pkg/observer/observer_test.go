//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//
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

	hubbleV1 "github.com/cilium/hubble/pkg/api/v1"
	hubbleCilium "github.com/cilium/hubble/pkg/cilium"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/cilium"
	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"
	fgsGrpc "github.com/isovalent/hubble-fgs/pkg/grpc"
	"github.com/isovalent/hubble-fgs/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/mountinfo"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"github.com/stretchr/testify/assert"
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

func newDefaultObserver(t *testing.T, opts ...testOption) (*ObserverKprobe, *testOptions) {
	// default values
	options := &testOptions{
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
		opt(options)
	}

	oo := &options.observer
	return NewObserverKprobe(observerTestDir,
			observerTestDir,
			"", "",
			oo.config, oo.tls, oo.tlstc, oo.pretty, oo.crd,
			0),
		options
}

func getDefaultObserver(t *testing.T, opts ...testOption) (*ObserverKprobe, error) {
	ctx, _ := context.WithCancel(context.Background())

	HubbleLib = fgsLib
	envFgsLib := os.Getenv("FGS_LIB")
	if envFgsLib != "" {
		HubbleLib = envFgsLib
	}
	procfs := os.Getenv("FGS_PROCFS")
	if procfs != "" {
		ProcFS = procfs
	}

	kprobe, o := newDefaultObserver(t, opts...)
	if testing.Verbose() {
		Verbosity = verboseLevel
	}

	if err := btf.InitCachedBTF(HubbleLib, ctx); err != nil {
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
	if err := btf.InitCachedBTF(HubbleLib, context.TODO()); err != nil {
		t.Fatalf("ConfigureBTF error: %s", err)
	}
	initialSensor := createInitialObserverSensor(kprobe.enableTLS, kprobe.enableTLSTC)
	if err := observerFindProgs(context.TODO(), initialSensor); err != nil {
		t.Fatalf("observerFindProgs error: %s", err)
	}
	ObserverLoadSensor(kprobe.bpfDir, kprobe.mapDir, kprobe.ciliumDir, context.TODO(), initialSensor)
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

	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	curlChecker := ec.ProcessWithCommand(
		ec.SuffixStringMatch("curl"), ec.FullStringMatch("127.0.0.1"),
	)
	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(selfChecker).
			HasParent().
			End(),
		ec.NewExecEventChecker().
			HasProcess(curlChecker).
			HasParent(selfChecker).
			End(),
		ec.NewConnectEventChecker().
			HasProcess(curlChecker).
			HasParent(selfChecker).
			HasDstIP("127.0.0.1").
			HasDstPort(80).
			End(),
	)

	kprobe, err := getDefaultObserverWithWatchers(t, withPretty())
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}

	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWGCurl(&execWG, &exitWG, "127.0.0.1")
	err = jsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)
	testDone(t, kprobe)
}

func TestExecEventClone(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	selfChecker := ec.NewProcessChecker().WithBinary(ec.SuffixStringMatch(selfBinary))
	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(ec.SuffixStringMatch("nc.traditional")).
		WithArguments(ec.FullStringMatch("-nvlp 8081"))
	ncCliChecker := ec.NewProcessChecker().
		WithBinary(ec.SuffixStringMatch("nc.traditional")).
		WithArguments(ec.FullStringMatch("127.0.0.1 8081 -e /bin/sh"))

	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(selfChecker).
			HasParent().
			End(),
		ec.NewExecEventChecker().
			HasProcess(ncSrvChecker).
			HasParent(selfChecker).
			End(),
		ec.NewListenEventChecker().
			HasProcess(ncSrvChecker).
			HasParent(selfChecker).
			HasIP("0.0.0.0").
			HasPort(8081).
			End(),
		ec.NewExecEventChecker().
			HasProcess(ncCliChecker).
			HasParent(selfChecker).
			End(),
		ec.NewConnectEventChecker().
			HasProcess(ncCliChecker).
			HasParent(selfChecker).
			HasDstIP("127.0.0.1").
			HasDstPort(8081).
			End(),
	)

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
	err = jsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)
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

	ok, err := JsonTestCompare(trace, exportFile, jsonRetries, 0)
	assert.NoError(t, err)
	assert.True(t, ok)
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

	ok, err := JsonTestCompare(trace, exportFile, jsonRetries, 0)
	assert.NoError(t, err)
	assert.True(t, ok)
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
	ok, err := JsonTestCompare(trace, exportFile, jsonRetries, 0)
	assert.NoError(t, err)
	assert.True(t, ok)
	testDone(t, kprobe)
}

func TestLoadTCTls(t *testing.T) {
	if kernels.MinKernelVersion("4.19.0") != true {
		return
	}
	kprobe, err := getDefaultObserverWithWatchers(t, withTLSTC())
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	testDone(t, kprobe)
}

var (
	traceTcTls13 = []*fgs.GetEventsResponse{
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
	tlstc = `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "tls"
spec:
  description: "tls parser spec"
  parser:
    tls:
      enable: true
      mode: "tc"
`
)

func TestTCTls13(t *testing.T) {
	if kernels.MinKernelVersion("4.19.0") != true {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	kprobe, err := getDefaultObserverWithWatchers(t, withTLSTC())
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWGCurl(&execWG, &exitWG, "https://google.com")
	ok, err := JsonTestCompare(traceTcTls13, exportFile, jsonRetries, 0)
	assert.NoError(t, err)
	assert.True(t, ok)
	testDone(t, kprobe)
}

func TestConfigTCTls13(t *testing.T) {
	if kernels.MinKernelVersion("4.19.0") != true {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	tlsConfig := []byte(tlstc)
	err := ioutil.WriteFile(testConfigFile, tlsConfig, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	kprobe, err := getDefaultObserverWithWatchers(t, withConfig(testConfigFile))
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
	}
	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWGCurl(&execWG, &exitWG, "https://google.com")
	ok, err := JsonTestCompare(traceTcTls13, exportFile, jsonRetries, 0)
	assert.NoError(t, err)
	assert.True(t, ok)
	testDone(t, kprobe)
}

func TestTCTls12(t *testing.T) {
	if kernels.MinKernelVersion("4.19.0") != true {
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
	ok, err := JsonTestCompare(trace, exportFile, jsonRetries, 0)
	assert.NoError(t, err)
	assert.True(t, ok)
	testDone(t, kprobe)
}

func TestListenAcceptClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	rcwd := cwdPath(true)
	fcwd := cwdPath(false)

	ncProc := &fgs.Process{
		Binary:    "nc.traditional",
		Arguments: "-nvlp 8081",
		Cwd:       fcwd,
	}
	selfProc := &fgs.Process{
		Binary: selfBinary,
		Cwd:    rcwd,
	}

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
					Process: ncProc,
					Parent:  selfProc,
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessListen{
				ProcessListen: &fgs.ProcessListen{
					Process: ncProc,
					Parent:  selfProc,
					Ip:      "0.0.0.0",
					Port:    &wrappers.UInt32Value{Value: 8081},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessAccept{
				ProcessAccept: &fgs.ProcessAccept{
					Process:    ncProc,
					Parent:     selfProc,
					SourceIp:   "127.0.0.1",
					SourcePort: &wrappers.UInt32Value{Value: 8081},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessClose{
				ProcessClose: &fgs.ProcessClose{
					Process:    ncProc,
					Parent:     selfProc,
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
						Process: ncProc,
						Parent: selfProc,
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
	ok, err := JsonTestCompare(trace, exportFile, jsonRetries, 0)
	assert.NoError(t, err)
	assert.True(t, ok)
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
	sensor := &ObserverSensor{name: "lseekTest", progs: progs, maps: maps}
	if err := observerFindProgs(ctx, sensor); err != nil {
		t.Fatalf("observerFindProgs error: %s", err)
	}
	if err := ObserverLoadSensor(kprobe.bpfDir, kprobe.mapDir, kprobe.ciliumDir, ctx, sensor); err != nil {
		kprobe.RemovePrograms()
		t.Fatalf("observerLoadSensor error: %s", err)
	}
	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWG.Wait()
	unix.Seek(-1, 0, 4444)
	exitWG.Wait()

	ok, err := JsonTestCompare(trace, exportFile, jsonRetries, 0)
	assert.NoError(t, err)
	assert.True(t, ok)

	observerUnloadSensor(kprobe.bpfDir, kprobe.mapDir, sensor, ctx)

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
	sensor := &ObserverSensor{name: sensorName, progs: progs, maps: maps}
	registerSensorAtInit(sensor)

	sensorCtl, err := StartSensorCtl(kprobe.bpfDir, kprobe.mapDir, kprobe.ciliumDir)
	if err != nil {
		t.Fatalf("startSensorController failed: %s", err)
	}
	kprobe.ObserverSync = sensorCtl
	defer func() {
		err := sensorCtl.stopSensorCtl(ctx)
		if err != nil {
			fmt.Printf("stopSensorController failed: %s\n", err)
		}
	}()

	if err := sensorCtl.EnableSensor(ctx, sensorName); err != nil {
		t.Fatalf("EnableSensor error: %s", err)
	}

	defer func() {
		err := sensorCtl.DisableSensor(ctx, sensorName)
		if err != nil {
			fmt.Printf("DisableSensor failed: %s\n", err)
		}
	}()

	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWG.Wait()
	unix.Seek(-1, 0, 4444)
	exitWG.Wait()

	ok, err := JsonTestCompare(trace, exportFile, jsonRetries, 0)
	assert.NoError(t, err)
	assert.True(t, ok)
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

	ok, err := JsonTestCompare(trace, exportFile, jsonRetries, 0)
	assert.NoError(t, err)
	assert.True(t, ok)
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

	ok, err := JsonTestCompare(trace, exportFile, jsonRetries, 0)
	assert.NoError(t, err)
	assert.True(t, ok)
	testDone(t, kprobe)
}
