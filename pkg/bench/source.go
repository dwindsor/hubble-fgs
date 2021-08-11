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
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/time/rate"
)

type SourceArgs struct {
	Duration   time.Duration // The test duration
	RatePerSec float64       // The number of steps per second to aim for
	ReqSize    int           // The size of a request, if applicable to the source.
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
	Forked     bool // true if the source is a forked process, e.g. don't deduct its cpu usage
}

type sourceName string

var (
	sources = map[sourceName]Source{
		"tcp-crr": tcpOrTLSCRRSource{tls: false},
		"tls-crr": tcpOrTLSCRRSource{tls: true},

		"tcp-rr": tcpOrTLSRRSource{tls: false},
		"tls-rr": tcpOrTLSRRSource{tls: true},

		"http-rr-go":     goHTTPRRSource{},
		"http-crr-go":    goHTTPCRRSource{},
		"http-rr-h2load": h2LoadSource{http2: false},

		"http2-rr-h2load": h2LoadSource{http2: true},

		"netperf-rr":  netperfSource{test: "TCP_RR"},
		"netperf-crr": netperfSource{test: "TCP_CRR"},
	}
)

func SourceNameOrPanic(s string) sourceName {
	if _, ok := sources[sourceName(s)]; ok {
		return sourceName(s)
	} else {
		log.Fatalf("Unknown source '%s', use one of: %s", s, strings.Join(SupportedSources(), ", "))
		return sourceName("")
	}
}

func (name sourceName) IsRequestResponse() bool {
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
	tls bool
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
	return sourceLoop(ctx, sinkPort, dialer, args.Duration, args.RatePerSec)
}

func sourceLoop(ctx context.Context, sinkPort int, dialer ContextDialer, duration time.Duration, ratePerSec float64) (SourceStats, error) {
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

	for {
		if ctx.Err() != nil {
			break
		}

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
		_, err = conn.Write(buf)
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
// Go HTTP Request-Response source
//

type goHTTPRRSource struct{}

func (src goHTTPRRSource) Run(ctx context.Context, sinkPort int, args SourceArgs) (stats SourceStats, err error) {
	runtime.LockOSThread()
	cpuUsageBefore := GetCPUUsage(CPU_USAGE_THIS_THREAD)
	limiter := rate.NewLimiter(rate.Limit(args.RatePerSec), 5 /* burst */)
	url := fmt.Sprintf("http://localhost:%d", sinkPort)
	tstart := time.Now()
	tend := tstart.Add(args.Duration)
	latencies := make([]time.Duration, 0, 1024)

	for {
		treq := time.Now()
		if ctx.Err() != nil || treq.After(tend) {
			break
		}

		if resp, err := http.Get(url); err != nil {
			stats.LastError = err.Error()
			stats.Errors++
		} else {
			if _, err := ioutil.ReadAll(resp.Body); err != nil {
				stats.LastError = err.Error()
				stats.Errors++
			}
			resp.Body.Close()
		}

		latencies = append(latencies, time.Since(treq))

		if args.RatePerSec > 0.0 {
			if err := limiter.Wait(ctx); err != nil {
				stats.LastError = err.Error()
				stats.Errors++
				log.Printf("limiter.Wait fail: %v\n", err)
				break
			}
		}
	}

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
	return
}

//
// Go HTTP Connect-Request-Response source
//

type goHTTPCRRSource struct{}

func (src goHTTPCRRSource) Run(ctx context.Context, sinkPort int, args SourceArgs) (stats SourceStats, err error) {
	runtime.LockOSThread()
	cpuUsageBefore := GetCPUUsage(CPU_USAGE_THIS_THREAD)
	limiter := rate.NewLimiter(rate.Limit(args.RatePerSec), 5 /* burst */)
	tstart := time.Now()
	tend := tstart.Add(args.Duration)
	latencies := make([]time.Duration, 0, 1024)
	dialer := &net.Dialer{Timeout: 5000 * time.Millisecond}
	target := "127.0.0.1:" + strconv.Itoa(sinkPort)
	req := []byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")

	logError := func(what string, err error) {
		log.Printf("%s error: %s\n", what, err)
		stats.LastError = err.Error()
		stats.Errors++
	}

	for {
		treq := time.Now()
		if ctx.Err() != nil || treq.After(tend) {
			break
		}

		if args.RatePerSec > 0.0 {
			if err = limiter.Wait(ctx); err != nil {
				stats.LastError = err.Error()
				stats.Errors++
				log.Printf("limiter.Wait fail: %v\n", err)
				break
			}
		}

		conn, err := dialer.DialContext(ctx, "tcp4", target)
		if err != nil {
			logError("Dial", err)
			continue
		}

		_, err = conn.Write(req)
		if err != nil {
			logError("conn.Write", err)
			conn.Close()
			continue
		}

		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			logError("http.ReadResponse", err)
			conn.Close()
			continue
		}

		_, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			logError("ioutil.ReadAll", err)
		}

		if err = resp.Body.Close(); err != nil {
			logError("resp.Body.Close", err)
		}
		if err = conn.Close(); err != nil {
			logError("conn.Close", err)
		}

		latencies = append(latencies, time.Since(treq))
	}

	n := len(latencies)
	tend = time.Now()
	elapsedSecs := float64(tend.Sub(tstart)) / float64(time.Second)
	stats.ActualRate = float64(n) / elapsedSecs
	sort.Sort(ByDuration(latencies))
	if n > 0 {
		stats.LatencyP50 = latencies[n/2]
		stats.LatencyP90 = latencies[(n*9)/10]
		stats.LatencyP99 = latencies[(n*99)/100]
	}
	stats.CPUUsage = GetCPUUsage(CPU_USAGE_THIS_THREAD).Sub(cpuUsageBefore)
	return
}

//
// Netperf source
//

type netperfSource struct {
	test string
}

func (src netperfSource) Run(ctx context.Context, sinkPort int, args SourceArgs) (stats SourceStats, err error) {
	cmd := exec.Command("netperf",
		"-H127.0.0.1",
		fmt.Sprintf("-p%d", sinkPort),
		fmt.Sprintf("-l%d", args.Duration/time.Second),
		"-P0", // No header
		"-t"+src.test,
		"--",
		"-o", "elapsed_time,throughput,p50_latency,p90_latency,p99_latency")

	out, err := cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("netperf failed: %w (out: %s)", err, out)
		return
	}

	stats.CPUUsage = CPUUsageFromRusage(cmd.ProcessState.SysUsage().(*syscall.Rusage))

	reader := csv.NewReader(bytes.NewReader(out))
	rs, err := reader.Read()
	if err != nil {
		err = fmt.Errorf("netperf csv output parse failed: %w", err)
		return
	}

	stats.ActualRate, err = strconv.ParseFloat(rs[1], 64)
	if err != nil {
		err = fmt.Errorf("netperf req rate parse failed: %w", err)
		return
	}
	stats.Forked = true
	stats.LatencyP50 = time.Duration(xAtoi(rs[2])) * time.Microsecond
	stats.LatencyP90 = time.Duration(xAtoi(rs[3])) * time.Microsecond
	stats.LatencyP99 = time.Duration(xAtoi(rs[4])) * time.Microsecond

	return
}

//
// h2load source
//
// https://nghttp2.org/documentation/h2load-howto.html

type h2LoadSource struct {
	http2 bool
}

func (src h2LoadSource) Run(ctx context.Context, sinkPort int, args SourceArgs) (stats SourceStats, err error) {
	nCPU := runtime.NumCPU()

	cmdArgs := []string{
		"run", "--rm", "--network=host",
		"--name=fgs-bench-h2load",
		"--entrypoint=/usr/bin/time", // For measuring CPU usage
		"joamaki/nghttp2-alpine",     // Custom build to get the latest version with --duration support.
		"h2load",
		fmt.Sprintf("--clients=%d", 10*nCPU), // 10 connections per thread.
		fmt.Sprintf("--threads=%d", nCPU),
		fmt.Sprintf("--duration=%ds", args.Duration/time.Second),
	}
	if !src.http2 {
		cmdArgs = append(cmdArgs, "--h1")
	}
	if args.RatePerSec > 0.0 {
		cmdArgs = append(cmdArgs, fmt.Sprintf("--rps=%d", int(args.RatePerSec)))
	}
	cmdArgs = append(cmdArgs, fmt.Sprintf("http://localhost:%d", sinkPort))

	cmd := exec.Command("docker", cmdArgs...)

	// Read combined output as 'time' outputs to stderr.
	out, err := cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("starting h2load failed: %w, out: %s", err, out)
		return
	}

	lines := strings.Split(string(out), "\n")

	var reqPerSec float64
	var max, mean time.Duration

	for _, line := range lines {
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
			max, _ = time.ParseDuration(maxS)
			mean, _ = time.ParseDuration(meanS)
		} else if strings.HasPrefix(line, "user") {
			// NOTE(JM): Couldn't figure out a better way for getting rusage out from a docker container that
			// terminates on its own. The cpuacct files are gone and unreadable even if opened before
			// the container exits. Using /usr/bin/time seemed easiest. Yes I spent too much time on this.
			var mins, secs float64
			if _, err = fmt.Sscanf(line, "user %fm %fs", &mins, &secs); err != nil {
				err = fmt.Errorf("failed to parse h2load output '%s': %w", line, err)
				return
			}
			stats.CPUUsage.UserTime = time.Duration(mins*float64(time.Minute)) + time.Duration(secs*float64(time.Second))
		} else if strings.HasPrefix(line, "sys") {
			var mins, secs float64
			if _, err = fmt.Sscanf(line, "sys %fm %fs", &mins, &secs); err != nil {
				err = fmt.Errorf("failed to parse h2load output '%s': %w", line, err)
				return
			}
			stats.CPUUsage.SystemTime = time.Duration(mins*float64(time.Minute)) + time.Duration(secs*float64(time.Second))
		}
	}

	stats.Forked = true
	stats.ActualRate = reqPerSec
	stats.LatencyP50 = mean
	stats.LatencyP90 = max // TODO: Fake p90/p99 for now. Could consider extending h2load or changing stats to min/max/mean?
	stats.LatencyP99 = max

	return
}

type ByDuration []time.Duration

func (a ByDuration) Len() int           { return len(a) }
func (a ByDuration) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByDuration) Less(i, j int) bool { return a[i] < a[j] }

type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func xAtoi(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return -1
	}
	return n
}
