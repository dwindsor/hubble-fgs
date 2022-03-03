package tcp

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/stretchr/testify/assert"
)

var (
	selfBinary  string
	fgsLib      string
	cmdWaitTime time.Duration
	client      bool
	server      bool
)

const (
	exportFile                        = "/tmp/hubble-fgs.gotest"
	testConfigFile                    = "/tmp/hubble-fgs.gotest.yaml"
	jsonRetries                       = 10
	IPPROTO_UDP                       = 0x11
	PROCESS_NETWORK_BURST_PROTO_SHIFT = 48
)

func init() {
	flag.StringVar(&fgsLib, "hubble-lib", "../../../bpf/objs/", "hubble lib directory (location of btf file and bpf objs). Will be overridden by an FGS_LIB env variable.")
	flag.DurationVar(&cmdWaitTime, "command-wait", 20000*time.Millisecond, "duration to wait for fgs to gather logs from commands")
	flag.BoolVar(&client, "client", false, "internal")
	flag.BoolVar(&server, "server", false, "internal")
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

func TestConnectEvent(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	curlChecker := ec.ProcessWithCommand(
		ec.SuffixStringMatch("curl"), ec.FullStringMatch("127.0.0.1"),
	)
	checker := ec.NewUnorderedMultiResponseChecker(
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
			HasProtocol(fgs.SocketProtocol_TCP).
			End(),
		ec.NewCloseEventChecker().
			HasProcess(curlChecker).
			HasParent(selfChecker).
			HasDstIP("127.0.0.1").
			HasDstPort(80).
			HasProtocol(fgs.SocketProtocol_TCP).
			HasType("connect").
			End(),
	)

	obs, err := observer.GetDefaultObserver(t, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	observer.LoopEvents(t, &doneWG, &readyWG, obs, ctx)
	observer.ExecWGCurl(&readyWG, "127.0.0.1")
	err = observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)
	observer.TestDone(t, obs)
}

func killAndWaitCommand(t *testing.T, cmd *exec.Cmd) {
	if cmd != nil {
		if cmd.Process != nil {
			cmd.Process.Kill()
		} else {
			t.Logf("Command %q process disappeared, skipping kill", cmd.Args[0])
		}
		_ = cmd.Wait()
	}
}

func TestExecEventClone(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	orig := "nc.traditional"
	server := orig
	client := server
	if _, err := exec.LookPath(server); err != nil {
		server = "nc"
		client = server

		if _, err := exec.LookPath(server); err != nil {
			t.Fatalf("Binary server=%q,client=%q doesn't exist on host machine, cannot continue",
				server, client)
		}

		t.Logf("Using server=%v,client=%v instead of original programs (server=%v,client=%v)",
			server, client, orig, orig)
	}

	selfChecker := ec.NewProcessChecker().WithBinary(ec.SuffixStringMatch(selfBinary))
	ncSrvChecker := ec.NewProcessChecker().
		WithBinary(ec.SuffixStringMatch(server)).
		WithArguments(ec.FullStringMatch("-nvlp 8081"))
	ncCliChecker := ec.NewProcessChecker().
		WithBinary(ec.SuffixStringMatch(client)).
		WithArguments(ec.FullStringMatch("127.0.0.1 8081"))

	checker := ec.NewUnorderedMultiResponseChecker(
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
			HasProtocol(fgs.SocketProtocol_TCP).
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
			HasProtocol(fgs.SocketProtocol_TCP).
			End(),
	)

	obs, err := observer.GetDefaultObserver(t, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	observer.LoopEvents(t, &doneWG, &readyWG, obs, ctx)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "127.0.0.1", "8081")
	assert.NoError(t, cmdClient.Start())

	err = observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)

	observer.TestDone(t, obs)
}

func getNCCommand(t *testing.T, orig string) string {
	if _, err := exec.LookPath(orig); err == nil {
		return orig
	}

	server := "nc"
	if _, err := exec.LookPath(server); err != nil {
		t.Fatalf("Binary %q doesn't exist on host machine, cannot continue", server)
	}
	t.Logf("Using %q instead of original program %q", server, orig)

	return server
}

func TestExistingListenEvent(t *testing.T) {
	server := getNCCommand(t, "nc.traditional")
	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	ncChecker := ec.ProcessWithCommand(
		ec.SuffixStringMatch(server), ec.FullStringMatch("-nvlp 8081"),
	)

	checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(selfChecker).
			HasParent().
			End(),
		ec.NewExecEventChecker().
			HasProcess(ncChecker).
			HasParent(selfChecker).
			End(),
		ec.NewListenEventChecker().
			HasProcess(ncChecker).
			HasParent(selfChecker).
			HasIP("0.0.0.0").
			HasPort(8081).
			HasProtocol(fgs.SocketProtocol_TCP).
			End(),
	)

	/* Start server before creating obs */
	cmdServer := exec.Command(server, "-nvlp", "8081")
	assert.NoError(t, cmdServer.Start())

	/* Create obs */
	obs, err := observer.GetDefaultObserver(t, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	killAndWaitCommand(t, cmdServer)

	err = observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	observer.TestDone(t, obs)
}

func TestExistingAcceptEvent(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.traditional")
	client := server

	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	ncChecker := ec.ProcessWithCommand(
		ec.SuffixStringMatch(server), ec.FullStringMatch("-nvlp 8081"),
	)

	checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(selfChecker).
			HasParent().
			End(),
		ec.NewExecEventChecker().
			HasProcess(ncChecker).
			HasParent(selfChecker).
			End(),
		ec.NewListenEventChecker().
			HasProcess(ncChecker).
			HasParent(selfChecker).
			HasIP("0.0.0.0").
			HasPort(8081).
			HasProtocol(fgs.SocketProtocol_TCP).
			End(),
		ec.NewAcceptEventChecker().
			HasProcess(ncChecker).
			HasParent(selfChecker).
			HasSrcIP("127.0.0.1").
			HasSrcPort(8081).
			HasProtocol(fgs.SocketProtocol_TCP).
			End(),
	)

	/* Start server before creating obs */
	cmdServer := exec.Command(server, "-nvlp", "8081")
	fmt.Printf("cmd: %s\n", cmdServer)
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)

	/* Create obs */
	obs, err := observer.GetDefaultObserver(t, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observer.LoopEvents(t, &doneWG, &readyWG, obs, ctx)

	readyWG.Wait()
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "127.0.0.1", "8081")
	fmt.Printf("cmd: %s\n", cmdClient)
	assert.NoError(t, cmdClient.Start())

	err = observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)

	observer.TestDone(t, obs)
}

func TestExistingRootCWDListenEvent(t *testing.T) {
	server := getNCCommand(t, "nc.traditional")
	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	ncChecker := ec.ProcessWithCommand(
		ec.SuffixStringMatch(server), ec.FullStringMatch("-nvlp 8081"),
	)

	checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(selfChecker).
			HasParent().
			End(),
		ec.NewExecEventChecker().
			HasProcess(ncChecker).
			HasParent(selfChecker).
			End(),
		ec.NewListenEventChecker().
			HasProcess(ncChecker).
			HasParent(selfChecker).
			HasIP("0.0.0.0").
			HasPort(8081).
			HasProtocol(fgs.SocketProtocol_TCP).
			End(),
	)

	path, err := os.Getwd()
	if err != nil {
		t.Fail()
	}

	/* Start server in '/' before creating observer */
	os.Chdir("/")
	cmdServer := exec.Command(server, "-nvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	os.Chdir(path)

	/* Create obs */
	obs, err := observer.GetDefaultObserver(t, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	killAndWaitCommand(t, cmdServer)

	err = observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	observer.TestDone(t, obs)
}

func TestListenAcceptClose(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	server := getNCCommand(t, "nc.traditional")
	client := server

	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	ncSrvChecker := ec.ProcessWithCommand(
		ec.SuffixStringMatch(server), ec.FullStringMatch("-nvlp 8081"),
	)

	checker := ec.NewUnorderedMultiResponseChecker(
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
			HasProtocol(fgs.SocketProtocol_TCP).
			End(),
		ec.NewAcceptEventChecker().
			HasProcess(ncSrvChecker).
			HasParent(selfChecker).
			HasSrcIP("127.0.0.1").
			HasSrcPort(8081).
			HasProtocol(fgs.SocketProtocol_TCP).
			End(),
		ec.NewCloseEventChecker().
			HasProcess(ncSrvChecker).
			HasParent(selfChecker).
			HasSrcIP("0.0.0.0").
			HasSrcPort(8081).
			HasProtocol(fgs.SocketProtocol_TCP).
			HasType("listen").
			End(),
		// TODO: it would be good if we could also check the close event on
		// the accept socket, but it goes into TIME_WAIT and then
		// eventually close and I don't want to wait for it. So we need
		// some go way to close the sockets.
	)

	exitChecker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExitEventChecker().
			HasProcess(ncSrvChecker).
			HasParent(selfChecker).
			HasSignal(syscall.SIGKILL).
			End(),
	)

	obs, err := observer.GetDefaultObserver(t, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observer.LoopEvents(t, &doneWG, &readyWG, obs, ctx)

	readyWG.Wait()
	cmdServer := exec.Command(server, "-nvlp", "8081")
	assert.NoError(t, cmdServer.Start())
	time.Sleep(1000 * time.Millisecond)
	cmdClient := exec.Command(client, "127.0.0.1", "8081")
	assert.NoError(t, cmdClient.Start())

	err = observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)

	killAndWaitCommand(t, cmdServer)
	killAndWaitCommand(t, cmdClient)

	err = observer.JsonTestCheck(t, exitChecker)
	assert.NoError(t, err)

	observer.TestDone(t, obs)
}

func TestDockerExistingListenEvent(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker not available. skipping test: %s", err)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	/* Start server before creating obs */
	observer.DockerRun(t, "--name", "fgs-test-server", "--entrypoint", "nc", "quay.io/cilium/alpine-curl:1.0", "-nvlp", "8081")
	observer.WaitForProcess("nc -nvlp 8081")
	time.Sleep(2 * time.Second)

	/* Create obs */
	obs, err := observer.GetDefaultObserver(t, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observer.LoopEvents(t, &doneWG, &readyWG, obs, ctx)

	// Ideally we would also verify the dockerID, but our current dockerID
	// scanner from procFS does not match github actions docker env that
	// does not prepend a 'docker' string to the cgroup name. For now
	// drop the comparison and just ensure we get the events.
	//fgsServerID := serverDockerID[:31]

	// Current code reports binary behind symlink in proc case (binaries running
	// before fgs starts), but in runtime event we report the name of the symlink.
	// In this test the difference is busybox vs nc.
	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	ncSrvChecker := ec.NewProcessChecker().
		WithBinary("/bin/busybox").
		WithArguments("-nvlp 8081").
		WithCWD("/").
		WithUID(0)

	checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(selfChecker).
			HasParent().
			End(),
		ec.NewExecEventChecker().
			HasProcess(ncSrvChecker).
			End(),
		ec.NewListenEventChecker().
			HasProcess(ncSrvChecker).
			HasIP("0.0.0.0").
			HasPort(8081).
			HasProtocol(fgs.SocketProtocol_TCP).
			End(),
	)

	err = observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)
	observer.TestDone(t, obs)
}

func TestDockerListenConnect(t *testing.T) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker not available. skipping test: %s", err)
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	obs, err := observer.GetDefaultObserver(t, fgsLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	observer.LoopEvents(t, &doneWG, &readyWG, obs, ctx)

	readyWG.Wait()
	serverDockerID := observer.DockerRun(t, "--name", "fgs-test-server", "--entrypoint", "nc", "quay.io/cilium/alpine-curl:1.0", "-nvlp", "8081")
	time.Sleep(1 * time.Second)
	clientDockerID := observer.DockerRun(t, "--link", "fgs-test-server", "--entrypoint", "nc", "quay.io/cilium/alpine-curl:1.0", "-p", "9876", "fgs-test-server", "8081")

	// FGS sends 31 bytes + \0 to user-space. Since it might have an arbitrary prefix,
	// match only on the first 24 bytes.
	fgsServerID := ec.PrefixStringMatch(serverDockerID[:24])
	fgsClientID := ec.PrefixStringMatch(clientDockerID[:24])

	selfChecker := ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))
	ncSrvChecker := ec.NewProcessChecker().
		WithBinary("/usr/bin/nc").
		WithArguments("-nvlp 8081").
		WithCWD("/").
		WithUID(0).
		WithDocker(fgsServerID)
	ncCliChecker := ec.NewProcessChecker().
		WithBinary("/usr/bin/nc").
		WithArguments("-p 9876 fgs-test-server 8081").
		WithCWD("/").
		WithUID(0).
		WithDocker(fgsClientID)

	checker := ec.NewUnorderedMultiResponseChecker(
		ec.NewExecEventChecker().
			HasProcess(selfChecker).
			HasParent().
			End(),
		ec.NewExecEventChecker().
			HasProcess(ncSrvChecker).
			End(),
		ec.NewListenEventChecker().
			HasProcess(ncSrvChecker).
			HasIP("0.0.0.0").
			HasPort(8081).
			End(),
		ec.NewExecEventChecker().
			HasProcess(ncCliChecker).
			End(),
		ec.NewConnectEventChecker().
			HasProcess(ncCliChecker).
			HasDstPort(8081).
			HasSrcPort(9876).
			HasProtocol(fgs.SocketProtocol_TCP).
			End(),
		ec.NewCloseEventChecker().
			HasProcess(ncSrvChecker).
			HasSrcIP("0.0.0.0").
			HasSrcPort(8081).
			HasType("listen").
			End(),
		ec.NewCloseEventChecker().
			HasProcess(ncCliChecker).
			HasDstPort(8081).
			HasSrcPort(9876).
			HasProtocol(fgs.SocketProtocol_TCP).
			HasType("connect").
			End(),
	)

	err = observer.JsonTestCheck(t, checker)
	assert.NoError(t, err)
	observer.TestDone(t, obs)
}
