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
	"bufio"
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/time/rate"
)

type SourceArgs struct {
	Duration       time.Duration // The test duration
	RatePerSec     float64       // The number of steps per second to aim for
	ReqSize        int           // The size of a request, if applicable to the source.
	NetNs          bool          // Network Namespace to run test
	DestinationIP  string
	WithConfidence bool // Set confidence interval in netperf tests
}

func (args *SourceArgs) String() string {
	return fmt.Sprintf("duration=%s, rate=%.2f, req-size=%d", args.Duration, args.RatePerSec, args.ReqSize)
}

type Source interface {
	Run(ctx context.Context, sinkPort int, args SourceArgs) (SourceStats, error)
}

type SourceStats struct {
	ActualRate float64
	Errors     int64
	LastError  string
	LatencyP50 time.Duration
	LatencyP90 time.Duration
	LatencyP99 time.Duration
	CPUUsage   CPUUsage
	CPUPercent CPUPercentages
	Forked     bool // true if the source is a forked process, e.g. don't deduct its cpu usage
}

type SourceName string

var (
	sources = map[SourceName]Source{
		"tcp-crr": tcpOrTLSCRRSource{tls: false},
		"tls-crr": tcpOrTLSCRRSource{tls: true},

		"tcp-rr": tcpOrTLSRRSource{tls: false},
		"tls-rr": tcpOrTLSRRSource{tls: true},

		// Fuzz test of the TLS parser. Just send random garbage on the
		// TLS parsed port.
		"tls-crr-fuzz": tcpOrTLSCRRSource{tls: false, fuzz: true},

		"http-rr-go":  goHTTPRRSource{},
		"http-crr-go": goHTTPCRRSource{},

		"http2-rr-go": goHTTP2RRSource{},

		"http-rr-h2load": h2LoadSource{http2: false},

		"http2-rr-h2load": h2LoadSource{http2: true},

		"netperf-rr":     netperfSource{test: "TCP_RR"},
		"netperf-crr":    netperfSource{test: "TCP_CRR"},
		"netperf-stream": netperfSource{test: "TCP_STREAM"},
	}
)

func SourceNameOrPanic(s string) SourceName {
	if _, ok := sources[SourceName(s)]; ok {
		return SourceName(s)
	}
	log.Fatalf("Unknown source '%s', use one of: %s", s, strings.Join(SupportedSources(), ", "))
	return SourceName("")
}

func (name SourceName) IsRequestResponse() bool {
	return strings.HasPrefix(string(name), "tcp-rr-") ||
		strings.HasPrefix(string(name), "tls-rr-") ||
		strings.HasPrefix(string(name), "http-rr-")
}

func SupportedSources() []string {
	keys := make([]string, 0, len(sources))
	for k := range sources {
		keys = append(keys, string(k))
	}
	return keys
}

//
// TCP/TLS Connect-Request-Response source
//

type tcpOrTLSCRRSource struct {
	tls  bool
	fuzz bool
}

func (src tcpOrTLSCRRSource) Run(ctx context.Context, sinkPort int, args SourceArgs) (SourceStats, error) {
	var dialer ContextDialer
	if src.tls {
		dialer = &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: 5000 * time.Millisecond},
			Config:    &tls.Config{InsecureSkipVerify: true},
		}
	} else {
		dialer = &net.Dialer{Timeout: 5000 * time.Millisecond}
	}
	return src.sourceLoop(ctx, sinkPort, dialer, args.Duration, args.RatePerSec)
}

func genRandomBytes(minSize, maxSize int32) []byte {
	n := minSize + rand.Int31n(maxSize-minSize)
	buf := make([]byte, n)
	_, err := crand.Read(buf)
	if err != nil {
		log.Fatalf("rand.Read(): %s", err)
	}
	return buf
}

func (src tcpOrTLSCRRSource) sourceLoop(ctx context.Context, sinkPort int, dialer ContextDialer, duration time.Duration, ratePerSec float64) (SourceStats, error) {
	// Lock to specific thread to collect rusage.
	runtime.LockOSThread()
	cpuUsageBefore := GetCPUUsage(CPU_USAGE_THIS_THREAD)
	limiter := rate.NewLimiter(rate.Limit(ratePerSec), 5 /* burst */)
	var stats SourceStats

	latencies := make([]time.Duration, 0, 1024)

	tstart := time.Now()
	tend := tstart.Add(duration)

	buf := []byte("hello world")
	rbuf := make([]byte, 1024)

	for ctx.Err() == nil {
		tconn := time.Now()
		if tconn.After(tend) {
			break
		}

		conn, err := dialer.DialContext(ctx, "tcp4", "127.0.0.1:"+strconv.Itoa(sinkPort))
		if err != nil {
			log.Printf("Dial error: %v\n", err)
			stats.LastError = err.Error()
			stats.Errors++
			continue
		}

		if src.fuzz {
			buf = genRandomBytes(32, 1024)
		}

		_, err = conn.Write(buf)
		if err != nil {
			log.Printf("Write error: %v\n", err)
			stats.LastError = err.Error()
			stats.Errors++
			continue
		}
		_, err = conn.Read(rbuf)
		if err != nil {
			log.Printf("Read error: %v\n", err)
			stats.LastError = err.Error()
			stats.Errors++
			continue
		}
		conn.Close()
		latencies = append(latencies, time.Since(tconn))

		if ratePerSec > 0.0 {
			err = limiter.Wait(ctx)
			if err != nil {
				stats.LastError = err.Error()
				stats.Errors++
				log.Printf("limiter.Wait fail: %v\n", err)
				break
			}
		}
	}
	tend = time.Now()
	elapsedSecs := float64(tend.Sub(tstart)) / float64(time.Second)
	n := len(latencies)
	stats.ActualRate = float64(n) / elapsedSecs

	if n > 0 {
		sort.Sort(ByDuration(latencies))
		stats.LatencyP50 = latencies[n/2]
		stats.LatencyP90 = latencies[(n*9)/10]
		stats.LatencyP99 = latencies[(n*99)/100]
	}

	stats.CPUUsage = GetCPUUsage(CPU_USAGE_THIS_THREAD).Sub(cpuUsageBefore)
	return stats, nil
}

//
// TCP/TLS Request-Response source
//

type tcpOrTLSRRSource struct {
	tls bool
}

func rrSourceLoop(ctx context.Context, sinkPort int, dialer ContextDialer, duration time.Duration, reqSize int) (stats SourceStats, err error) {
	// Lock to specific thread to collect rusage.
	runtime.LockOSThread()
	cpuUsageBefore := GetCPUUsage(CPU_USAGE_THIS_THREAD)
	tstart := time.Now()
	tend := tstart.Add(duration)
	latencies := make([]time.Duration, 0, 1024)
	buf := bytes.Repeat([]byte("X"), reqSize)
	rbuf := make([]byte, 8192)

	conn, err := dialer.DialContext(ctx, "tcp4", "127.0.0.1:"+strconv.Itoa(sinkPort))
	if err != nil {
		log.Printf("dial error: %v\n", err)
		stats.LastError = err.Error()
		stats.Errors++
		return
	}

	for {
		treq := time.Now()
		if ctx.Err() != nil || treq.After(tend) {
			break
		}
		_, err = ChunkingConn{conn}.Write(buf)
		if err != nil {
			log.Printf("Write error: %v\n", err)
			stats.LastError = err.Error()
			stats.Errors++
			continue
		}
		_, err = conn.Read(rbuf)
		if err != nil {
			log.Printf("Read error: %v", err)
			stats.LastError = err.Error()
			stats.Errors++
			continue
		}
		latencies = append(latencies, time.Since(treq))
	}
	conn.Close()

	n := len(latencies)
	tend = time.Now()
	elapsedSecs := float64(tend.Sub(tstart)) / float64(time.Second)
	stats.ActualRate = float64(n) / elapsedSecs
	if n > 0 {
		sort.Sort(ByDuration(latencies))
		stats.LatencyP50 = latencies[n/2]
		stats.LatencyP90 = latencies[(n*9)/10]
		stats.LatencyP99 = latencies[(n*99)/100]
	}
	stats.CPUUsage = GetCPUUsage(CPU_USAGE_THIS_THREAD).Sub(cpuUsageBefore)
	return stats, nil
}

func (src tcpOrTLSRRSource) Run(ctx context.Context, sinkPort int, args SourceArgs) (SourceStats, error) {
	var dialer ContextDialer

	if src.tls {
		dialer = &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: 5000 * time.Millisecond},
			Config:    &tls.Config{InsecureSkipVerify: true},
		}
	} else {
		dialer = &net.Dialer{Timeout: 5000 * time.Millisecond}
	}
	return rrSourceLoop(ctx, sinkPort, dialer, args.Duration, args.ReqSize)
}

//
// Go HTTP/1.1 Request-Response source
//

type goHTTPRRSource struct{}

func (src goHTTPRRSource) Run(ctx context.Context, sinkPort int, args SourceArgs) (stats SourceStats, err error) {
	url := fmt.Sprintf("http://127.0.0.1:%d", sinkPort)
	act := func() error {
		resp, err := http.Get(url)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if _, err := io.ReadAll(resp.Body); err != nil {
			return err
		}
		return nil
	}
	return genGoSource(ctx, sinkPort, args, act)
}

//
// Go HTTP/2 Request-Response source
//

type goHTTP2RRSource struct{}

func (src goHTTP2RRSource) Run(ctx context.Context, sinkPort int, args SourceArgs) (stats SourceStats, err error) {
	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	client := http.Client{
		Transport: &http.Transport{
			Protocols: &protocols,
			// Fake a TLS connection so the Go HTTP client uses HTTP/2.
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				conn, err := d.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				// Use a ChunkingConn to split the writes into random-sized chunks
				// to stress the http/2 parser implementation.
				return ChunkingConn{conn}, nil
			},
		},
		Timeout: time.Second,
	}
	url := fmt.Sprintf("http://127.0.0.1:%d", sinkPort)
	methodCounter := 0
	act := func() error {
		methodCounter++ // thread-unsafe, but doesn't matter for this case.
		var (
			resp *http.Response
			err  error
		)
		if methodCounter%2 == 0 {
			resp, err = client.Get(url)
			if err != nil {
				return err
			}
		} else {
			resp, err = client.Post(url, "text/plain", bytes.NewBufferString("hello world"))
			if err != nil {
				return err
			}
		}
		defer resp.Body.Close()
		if _, err := io.ReadAll(resp.Body); err != nil {
			return err
		}
		return nil
	}
	return genGoSource(ctx, sinkPort, args, act)
}

//
// Go HTTP Connect-Request-Response source
//

type goHTTPCRRSource struct{}

func (src goHTTPCRRSource) Run(ctx context.Context, sinkPort int, args SourceArgs) (stats SourceStats, err error) {
	dialer := &net.Dialer{Timeout: 5000 * time.Millisecond}
	target := "127.0.0.1:" + strconv.Itoa(sinkPort)
	req := []byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	act := func() error {
		conn, err := dialer.DialContext(ctx, "tcp4", target)
		if err != nil {
			return fmt.Errorf("dial: %w", err)
		}
		defer conn.Close()

		_, err = ChunkingConn{conn}.Write(req)
		if err != nil {
			return fmt.Errorf("write: %w", err)
		}

		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			return fmt.Errorf("http.ReadResponse: %w", err)
		}
		defer resp.Body.Close()

		_, err = io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("readAll: %w", err)
		}
		return nil
	}
	return genGoSource(ctx, sinkPort, args, act)
}

func genGoSource(ctx context.Context, _ int, args SourceArgs, act func() error) (stats SourceStats, err error) {
	wg := sync.WaitGroup{}
	mu := sync.Mutex{}
	nthreads := runtime.NumCPU()
	limiter := rate.NewLimiter(rate.Limit(args.RatePerSec), 5 /* burst */)
	tstart := time.Now()
	latencies := make([]time.Duration, 0, 1024)

	// Use a separate context for stopping the source after requested duration is reached.
	// Needed to cancel the limiter.Wait call without having to cancel the parent context.
	srcCtx, srcCancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-time.After(args.Duration):
			srcCancel()
		case <-ctx.Done():
			srcCancel()
		}
	}()

	logError := func(err error) {
		log.Printf("Error: %s\n", err)
		mu.Lock()
		stats.LastError = err.Error()
		stats.Errors++
		mu.Unlock()
	}

	stats.CPUUsage = CPUUsage{}
	wg.Add(nthreads)
	for range nthreads {
		go func() {
			runtime.LockOSThread()
			latenciesPerThread := make([]time.Duration, 0, 1024)
			cpuUsageBefore := GetCPUUsage(CPU_USAGE_THIS_THREAD)
			for srcCtx.Err() == nil {
				treq := time.Now()

				if args.RatePerSec > 0.0 {
					if err := limiter.Wait(srcCtx); err != nil {
						if !errors.Is(err, context.Canceled) {
							logError(fmt.Errorf("limiter.Wait: %w", err))
						}
						break
					}
				}

				if err := act(); err != nil {
					logError(err)
				}

				latenciesPerThread = append(latenciesPerThread, time.Since(treq))
			}

			mu.Lock()
			latencies = append(latencies, latenciesPerThread...)
			stats.CPUUsage = stats.CPUUsage.Add(GetCPUUsage(CPU_USAGE_THIS_THREAD).Sub(cpuUsageBefore))
			mu.Unlock()
			wg.Done()
		}()
	}

	wg.Wait()

	n := len(latencies)
	tend := time.Now()
	elapsedSecs := float64(tend.Sub(tstart)) / float64(time.Second)
	stats.ActualRate = float64(n) / elapsedSecs
	sort.Sort(ByDuration(latencies))
	if n > 0 {
		stats.LatencyP50 = latencies[n/2]
		stats.LatencyP90 = latencies[(n*9)/10]
		stats.LatencyP99 = latencies[(n*99)/100]
	}
	return
}

//
// Netperf source
//

type netperfSource struct {
	test string
}

func (src netperfSource) Run(_ context.Context, sinkPort int, args SourceArgs) (stats SourceStats, err error) {
	var res []byte

	if args.RatePerSec > 0.0 {
		log.Printf("Netperf does not support fixed rate, ignoring requested rate.\n")
	}

	port := findFreePort()

	if args.NetNs {
		cmdDocker := exec.Command(
			"docker", "run", "--rm", "--network=none",
			"--detach", "--cap-add=NET_ADMIN",
			"--name=fgs-bench-netperf",
			"--entrypoint=/usr/bin/time",
			"joamaki/netperf-docker", // Custom build for the EAGAIN fix
			"-p", "netserver",
			"-D", "-N", "-f", "-4", fmt.Sprintf("-p %d", port),
		)

		res, _ = cmdDocker.CombinedOutput()
		/* Appears I need a retry here as the above output and GetFromDocker race. */
		var nsDocker netns.NsHandle
		retry := 0

		for {
			nsDocker, err = netns.GetFromDocker(string(res[:12]))
			if err == nil {
				break
			}
			if retry > 10 {
				return stats, fmt.Errorf("netserver network namespace unknown: %s result (%s)", err, res)
			}
			time.Sleep(5 * time.Second)
			retry++
		}
		createInterface(&nsDocker, senderName, senderIP)
	} else {
		cmdDocker := exec.Command(
			"docker", "ps", "-aqf", "name=fgs-bench-netserver",
		)
		res, _ = cmdDocker.CombinedOutput()
	}

	cmdDockerKill := exec.Command(
		"docker", "kill", string(res[:12]),
	)
	defer cmdDockerKill.CombinedOutput()

	argsNetperf := []string{"exec", string(res[:12]), "netperf"}
	if args.WithConfidence {
		argsNetperf = append(argsNetperf, "-I 99,1")
	}
	argsNetperf = append(argsNetperf,
		fmt.Sprintf("-H%s", args.DestinationIP),
		fmt.Sprintf("-p%d", sinkPort),
		fmt.Sprintf("-l%d", args.Duration/time.Second),
		"-P0", // No header
		"-c", "-C",
		"-T 1,2",
		"-t"+src.test,
		"--",
		"-o", "elapsed_time,throughput,p50_latency,p90_latency,p99_latency,local_cpu_percent_user,local_cpu_percent_system,remote_cpu_percent_user,remote_cpu_percent_system",
	)
	cmdNetperf := exec.Command("docker", argsNetperf...)
	log.Printf("netperf source command: %s\n", cmdNetperf)

	// Read combined output as 'time' outputs to stderr.
	out, err := cmdNetperf.CombinedOutput()
	if err != nil {
		return stats, fmt.Errorf("starting netperf failed: %w, out: %s", err, out)
	}

	stats.CPUUsage, _ = CPUUsageFromTime(string(out),
		func(line string) {
			var localCpuUser, localCpuSystem, remoteCpuUser, remoteCpuSystem float64
			var elapsed, throughput float64
			var l50us, l90us, l99us int

			if _, err = fmt.Sscanf(line, "%f,%f,%d,%d,%d,%f,%f,%f,%f",
				&elapsed, &throughput, &l50us, &l90us, &l99us,
				&localCpuUser, &localCpuSystem,
				&remoteCpuUser, &remoteCpuSystem); err != nil {
				err = fmt.Errorf("failed to parse netperf output '%s': %w", line, err)
				return
			}
			stats.ActualRate = throughput
			stats.LatencyP50 = time.Duration(l50us) * time.Microsecond
			stats.LatencyP90 = time.Duration(l90us) * time.Microsecond
			stats.LatencyP99 = time.Duration(l99us) * time.Microsecond
			stats.CPUPercent.SourceCpuUser = localCpuUser
			stats.CPUPercent.SourceCpuSystem = localCpuSystem
			stats.CPUPercent.RemoteCpuUser = remoteCpuUser
			stats.CPUPercent.RemoteCpuSystem = remoteCpuSystem
		})

	stats.Forked = true
	return
}

//
// h2load source
//
// https://nghttp2.org/documentation/h2load-howto.html

type h2LoadSource struct {
	http2 bool
}

func (src h2LoadSource) Run(_ context.Context, sinkPort int, args SourceArgs) (stats SourceStats, err error) {
	nCPU := runtime.NumCPU()
	nClients := 5 * nCPU

	h2loadArgs := []string{
		fmt.Sprintf("--clients=%d", nClients),
		fmt.Sprintf("--threads=%d", nCPU),
		fmt.Sprintf("--duration=%ds", args.Duration/time.Second),
		"--max-concurrent-streams=5",
	}

	cmdArgs := []string{
		"run", "--rm", "--network=host",
		"--entrypoint=/usr/bin/time",
		"--name=fgs-bench-h2load",
		"joamaki/nghttp2-alpine", // Custom build to get the latest version with --duration support.
		"-p", "h2load",
	}
	cmdArgs = append(cmdArgs, h2loadArgs...)
	if !src.http2 {
		cmdArgs = append(cmdArgs, "--h1")
	}

	if args.RatePerSec > 0.0 {
		cmdArgs = append(cmdArgs, fmt.Sprintf("--rps=%f", args.RatePerSec/float64(nClients)))
	}
	cmdArgs = append(cmdArgs, fmt.Sprintf("http://localhost:%d", sinkPort))

	cmd := exec.Command("docker", cmdArgs...)

	// Read combined output as 'time' outputs to stderr.
	out, err := cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("starting h2load failed: %w, out: %s", err, out)
		return
	}

	var reqPerSec float64
	var maximum, mean time.Duration

	stats.CPUUsage, _ = CPUUsageFromTime(string(out),
		func(line string) {
			if strings.HasPrefix(line, "finished") {
				var durationS, throughputS string
				if _, err = fmt.Sscanf(strings.ReplaceAll(line, ",", ""),
					"finished in %s %f req/s %s",
					&durationS, &reqPerSec, &throughputS); err != nil {
					err = fmt.Errorf("failed to parse h2load output '%s': %w", line, err)
					return
				}
			} else if strings.HasPrefix(line, "requests") {
				var total, started, done, succeeded, failed, errored, timeout int64
				if _, err = fmt.Sscanf(line, "requests: %d total, %d started, %d done, %d succeeded, %d failed, %d errored, %d timeout",
					&total, &started, &done, &succeeded, &failed, &errored, &timeout); err != nil {
					err = fmt.Errorf("failed to parse h2load output '%s': %w", line, err)
					return
				}
				stats.Errors = errored
				if errored > 0 {
					stats.LastError = "h2load encountered errors"
				}
			} else if strings.HasPrefix(line, "time for request") {
				var minS, maxS, meanS, sdS, sdSP string
				if _, err = fmt.Sscanf(line, "time for request: %s %s %s %s %s", &minS, &maxS, &meanS, &sdS, &sdSP); err != nil {
					err = fmt.Errorf("failed to parse h2load output '%s': %w", line, err)
					return
				}
				maximum, _ = time.ParseDuration(maxS)
				mean, _ = time.ParseDuration(meanS)
			}
		})

	stats.Forked = true
	stats.ActualRate = reqPerSec
	stats.LatencyP50 = mean
	stats.LatencyP90 = maximum // TODO: Fake p90/p99 for now. Could consider extending h2load or changing stats to min/max/mean?
	stats.LatencyP99 = maximum

	return
}

type ByDuration []time.Duration

func (a ByDuration) Len() int           { return len(a) }
func (a ByDuration) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByDuration) Less(i, j int) bool { return a[i] < a[j] }

type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ChunkingConn is a net.Conn that splits up a Write() into multiple random sized chunks.
type ChunkingConn struct {
	net.Conn
}

func (cc ChunkingConn) Write(b []byte) (int, error) {
	written := 0

	for remaining := len(b); remaining > 0; {
		size := 1 + rand.Intn(remaining)
		n, err := cc.Conn.Write(b[written : written+size])
		written += n
		remaining -= n
		if err != nil {
			return written, err
		}
	}

	return written, nil
}
