// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bench

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	_ "embed"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netns"
)

type SinkStats struct {
	Forked   bool // true if the sink forks a separate process
	CPUUsage CPUUsage
}

type SinkName string

type Sink interface {
	Start(ctx context.Context, ns bool) (int, chan SinkStats, error)
}

var (
	//go:embed cert.pem
	certPem []byte

	//go:embed key.pem
	keyPem []byte

	sinks = map[SinkName]Sink{
		"tcp-go":      tcpOrTLSSink{tls: false},
		"http-go":     goHTTPSink{},
		"http2-go":    goHTTP2Sink{},
		"http-nginx":  nginxSink{},
		"tls-go":      tcpOrTLSSink{tls: true},
		"tcp-fuzz-go": tcpOrTLSSink{tls: false, fuzz: true},
		"netperf":     netperfSink{},
	}
)

func SinkNameOrPanic(s string) SinkName {
	if _, ok := sinks[SinkName(s)]; ok {
		return SinkName(s)
	}
	log.Fatalf("Unknown sink '%s', use on of: %s", s, strings.Join(SupportedSinks(), ", "))
	return SinkName("")
}

func SupportedSinks() []string {
	keys := make([]string, 0, len(sinks))
	for k := range sinks {
		keys = append(keys, string(k))
	}
	return keys
}

//
// TCP/TLS sink
//

type tcpOrTLSSink struct {
	tls  bool
	fuzz bool
}

func (sink tcpOrTLSSink) Start(ctx context.Context, _ bool) (int, chan SinkStats, error) {
	listener, port, err := tcpListen(ctx)
	if err != nil {
		return -1, nil, fmt.Errorf("TCP listen error: %w", err)
	}

	if sink.tls {
		cert, err := tls.X509KeyPair(certPem, keyPem)
		if err != nil {
			listener.Close()
			return -1, nil, fmt.Errorf("X509KeyPair error: %w", err)
		}
		listener = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{cert}})
	}
	statsCh := make(chan SinkStats, 1)
	withStats(statsCh, func() {
		sink.acceptCopyLoop(listener)
		listener.Close()
	})

	return port, statsCh, nil
}

func (sink tcpOrTLSSink) acceptCopyLoop(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		if sink.fuzz {
			// Discard random amount, source expected to always write
			// at least 32 bytes.
			c.Read(make([]byte, rand.Int31n(32)))

			// Write random amount of random
			n := rand.Int31n(1024)
			buf := make([]byte, n)
			crand.Read(buf)
			c.Write(buf)
		} else {
			io.Copy(c, c)
		}
		c.Close()
	}
}

func tcpListen(ctx context.Context) (net.Listener, int, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, -1, err
	}

	go func() {
		<-ctx.Done()
		l.Close()
	}()

	port := l.Addr().(*net.TCPAddr).Port
	return l, port, nil
}

//
// HTTP/1.1 sink
//

type goHTTPSink struct{}

func (sink goHTTPSink) Start(ctx context.Context, _ bool) (int, chan SinkStats, error) {
	l, port, err := tcpListen(ctx)
	if err != nil {
		return -1, nil, fmt.Errorf("TCP listen error: %w", err)
	}

	buf := []byte("helloworld")

	statsCh := make(chan SinkStats, 1)
	go func() {
		// Start blocking serve. Will exit when the listener is closed.
		http.Serve(l,
			http.HandlerFunc(
				func(w http.ResponseWriter, _ *http.Request) {
					w.Write(buf)
				}),
		)

		// TODO: No good way to collect CPU usage statistics since "net/http" forks
		// bunch of goroutines.
		statsCh <- SinkStats{Forked: false}
	}()
	return port, statsCh, nil
}

//
// HTTP/2.0 sink

type goHTTP2Sink struct{}

func (sink goHTTP2Sink) Start(ctx context.Context, _ bool) (int, chan SinkStats, error) {
	l, port, err := tcpListen(ctx)
	if err != nil {
		return -1, nil, fmt.Errorf("TCP listen error: %w", err)
	}
	l = ChunkingListener{l}

	buf := []byte("helloworld")

	statsCh := make(chan SinkStats, 1)
	go func() {
		// Start blocking serve. Will exit when the listener is closed.
		handler := http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {
				w.Write(buf)
			})
		s := http.Server{
			Handler: handler,
		}
		s.Protocols = new(http.Protocols)
		s.Protocols.SetHTTP1(true)
		s.Protocols.SetUnencryptedHTTP2(true)
		s.Serve(l)

		// TODO: No good way to collect CPU usage statistics since "net/http" forks
		// bunch of goroutines.
		statsCh <- SinkStats{Forked: false}
	}()
	return port, statsCh, nil
}

//
// NGINX sink
//

type nginxSink struct{}

func (sink nginxSink) Start(ctx context.Context, _ bool) (int, chan SinkStats, error) {
	cmd := exec.Command(
		"docker", "run", "--rm", "--network=host",
		"--name=fgs-bench-nginx",
		"nginx",
		"bash", "-c", "time -p nginx -g \"daemon off;\"",
	)

	statsCh := make(chan SinkStats, 1)
	go func() {
		stats := SinkStats{Forked: true}

		var b bytes.Buffer
		cmd.Stdout = io.Discard
		cmd.Stderr = &b
		err := cmd.Run()
		if err != nil {
			log.Printf("nginx failed %s: %s\n", b.String(), err)
		} else {
			stats.CPUUsage, _ = CPUUsageFromTime(b.String(), func(_ string) {})
		}
		statsCh <- stats
	}()

	go func() {
		<-ctx.Done()
		exec.Command("docker", "exec", "fgs-bench-nginx", "nginx", "-s", "stop").Run()
		exec.Command("docker", "stop", "fgs-bench-nginx").Run()
	}()

	// Wait for nginx to be ready.
	if !ProbeTCPPort(80, nil) {
		exec.Command("docker", "stop", "fgs-bench-nginx").Run()
		return -1, nil, fmt.Errorf("nginx did not start up on time")
	}

	return 80, statsCh, nil
}

//
// Netperf sink
//

type netperfSink struct{}

func (sink netperfSink) Start(ctx context.Context, ns bool) (int, chan SinkStats, error) {
	var nsDocker *netns.NsHandle

	port := findFreePort()

	pull := exec.Command(
		"docker", "image", "pull",
		"joamaki/netperf-docker",
	)
	pull.CombinedOutput()

	cmd := exec.Command(
		"docker", "run", "--rm", "--network=none",
		"--detach", "--cap-add=NET_ADMIN",
		"--name=fgs-bench-netserver",
		"--entrypoint=/usr/bin/time",
		"joamaki/netperf-docker",
		"-p", "netserver",
		"-D", "-N", "-f", "-4", fmt.Sprintf("-p %d", port),
	)

	statsCh := make(chan SinkStats, 1)
	readyToProbe := make(chan bool, 1)
	go func() {
		stats := SinkStats{Forked: true}
		var b bytes.Buffer
		var err error

		res, _ := cmd.CombinedOutput()
		stats.CPUUsage, err = CPUUsageFromTime(b.String(), func(_ string) {})
		if err != nil {
			log.Printf("netserver CPU usage parsing failed: %s\n", err)
		}
		retry := 0
		for {
			strres := string(res)
			strres = strings.TrimSpace(strres[:12])
			nsd, err := netns.GetFromDocker(strres)
			if err == nil {
				nsDocker = &nsd
				break
			}
			if retry > 10 {
				help := exec.Command(
					"docker", "ps",
				)

				helpLog, _ := help.CombinedOutput()
				log.Printf("netserver 'docker run' returned: %s\n", strres)
				log.Printf("docker ps: %s\n", helpLog)
				log.Printf("netserver network namespace unknown: %s\n", err)
				return
			}
			time.Sleep(5 * time.Second)
			retry++
		}
		if ns {
			createInterface(nsDocker, receiverName, receiverIP)
		}
		readyToProbe <- true
		statsCh <- stats
	}()

	go func() {
		<-ctx.Done()
		exec.Command("docker", "exec", "fgs-bench-netserver", "killall", "netserver").Run()
		exec.Command("docker", "stop", "fgs-bench-netserver").Run()
	}()

	<-readyToProbe
	// Wait for it to be ready.
	if !ProbeTCPPort(port, nsDocker) {
		return -1, nil, fmt.Errorf("netserver did not start up on time")
	}

	return port, statsCh, nil
}

// Helper for non-forking sinks to collect statistics.
func withStats(sinkStats chan SinkStats, run func()) {
	stats := SinkStats{Forked: false}

	go func() {
		// Lock to specific thread so we can collect stats.
		// The sink sholudn't fork goroutines as those won't
		// be included in the cpu usage stats.
		runtime.LockOSThread()

		cpuUsageBefore := GetCPUUsage(CPU_USAGE_THIS_THREAD)
		run()
		stats.CPUUsage = GetCPUUsage(CPU_USAGE_THIS_THREAD).Sub(cpuUsageBefore)
		sinkStats <- stats
	}()
}

// findFreePort tries to pick a random available port number. Used for
// sinks that don't have a good way of letting the kernel allocate the port
// number (e.g. netserver). We need this for netserver as it's not setting
// SO_REUSEPORT and hence fails if two netperf tests are run back to back
// on same port.
func findFreePort() int {
	taken := tcpListenPorts()
	for try := 0; try < 10; try++ {
		port := 14000 + rand.Intn(10000)
		if _, ok := taken[port]; ok {
			continue
		}
		return port
	}
	log.Fatal("Failed to find free port")
	return -1
}

func tcpListenPorts() map[int]struct{} {
	ports := make(map[int]struct{})
	cmd := exec.Command("/bin/sh", "-c", "ss -l -n -t -H|awk '{ split($4,x,\":\"); print x[length(x)] }'|sort -nu")
	out, err := cmd.Output()
	if err != nil {
		log.Printf("Failed to get TCP listen ports: %s", err)
		return ports
	}
	for _, s := range strings.Split(string(out), "\n") {
		if s == "" {
			continue
		}
		p, err := strconv.ParseInt(s, 10, 32)
		if err != nil {
			log.Printf("Failed to parse port number: %s", err)
		} else {
			ports[int(p)] = struct{}{}
		}
	}
	return ports
}

// ChunkingListener returns a listener that returns connections, which
// split up writes into multiple random-sized chunks.
type ChunkingListener struct {
	net.Listener
}

func (cl ChunkingListener) Accept() (net.Conn, error) {
	conn, err := cl.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return ChunkingConn{conn}, nil
}
