//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package bench

import (
	"context"
	"crypto/tls"
	_ "embed"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

type SinkStats struct {
	Forked   bool // true if the sink forks a separate process
	CPUUsage CPUUsage
}

type sinkName string

type Sink interface {
	Start(ctx context.Context) (int, chan SinkStats, error)
}

var (
	//go:embed cert.pem
	certPem []byte

	//go:embed key.pem
	keyPem []byte

	sinks = map[sinkName]Sink{
		"tcp-go":     tcpOrTLSSink{tls: false},
		"http-go":    goHTTPSink{},
		"http-nginx": nginxSink{},
		"tls-go":     tcpOrTLSSink{tls: true},
		"netperf":    netperfSink{},
	}
)

func SinkNameOrPanic(s string) sinkName {
	if _, ok := sinks[sinkName(s)]; ok {
		return sinkName(s)
	} else {
		log.Fatalf("Unknown sink '%s', use on of: %s", s, strings.Join(SupportedSources(), ", "))
		return sinkName("")
	}
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
	tls bool
}

func (sink tcpOrTLSSink) Start(ctx context.Context) (int, chan SinkStats, error) {
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
		io.Copy(c, c)
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
//

type goHTTPSink struct{}

func (sink goHTTPSink) Start(ctx context.Context) (int, chan SinkStats, error) {
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
				func(w http.ResponseWriter, r *http.Request) {
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
// NGINX sink
//

type nginxSink struct{}

func (sink nginxSink) Start(ctx context.Context) (int, chan SinkStats, error) {
	cmd := exec.Command(
		"docker", "run", "--detach", "--rm", "--network=host",
		"--name=fgs-bench-nginx",
		"nginx",
	)

	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return -1, nil, fmt.Errorf("failed to start nginx: %w", err)
	}
	containerID := strings.TrimSpace(string(out))

	statsCh := make(chan SinkStats, 1)
	go func() {
		<-ctx.Done()
		stats := SinkStats{Forked: true}
		stats.CPUUsage = CPUUsageFromCPUAcct(containerID)
		exec.Command("docker", "stop", containerID).Run()
		statsCh <- stats
	}()

	// Wait for nginx to be ready.
	if !ProbeTCPPort(80) {
		exec.Command("docker", "stop", containerID).Run()
		return -1, nil, fmt.Errorf("nginx did not start up on time")
	}

	return 80, statsCh, nil
}

//
// Netperf sink
//

type netperfSink struct{}

func (sink netperfSink) Start(ctx context.Context) (int, chan SinkStats, error) {
	port := findFreePort()
	cmd := exec.Command("netserver", "-D", "-N", "-f", "-4", "-p", strconv.Itoa(port))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	log.Printf("Spawning netserver on port %d\n", port)

	// netserver sets the output file permissions and with -D the output
	// file is /dev/null, so don't run netserver as root to avoid changing
	// permissions of /dev/null.
	// https://github.com/HewlettPackard/netperf/issues/26
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: 1},
	}
	if err := cmd.Start(); err != nil {
		return -1, nil, fmt.Errorf("failed to start netserver: %w", err)
	}

	statsCh := make(chan SinkStats, 1)
	// Terminate the process gracefully as netserver forks.
	go func() {
		<-ctx.Done()
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
		statsCh <- SinkStats{
			Forked:   true,
			CPUUsage: CPUUsageFromRusage(cmd.ProcessState.SysUsage().(*syscall.Rusage)),
		}
	}()

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
