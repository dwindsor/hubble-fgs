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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"log"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"time"

	"golang.org/x/time/rate"
)

type SourceStats struct {
	ActualConnRate float64
	ActualReqRate float64
	Errors     int64
	LastError  string
	LatencyP50 time.Duration
	LatencyP90 time.Duration
	LatencyP99 time.Duration
}

type ByDuration []time.Duration
func (a ByDuration) Len() int           { return len(a) }
func (a ByDuration) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByDuration) Less(i, j int) bool { return a[i] < a[j] }

type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func sourceLoop(ctx context.Context, sinkPort int, dialer ContextDialer, n int, ratePerSec float64) SourceStats {
	limiter := rate.NewLimiter(rate.Limit(ratePerSec), 5 /* burst */)
	var stats SourceStats

	latencies := make([]time.Duration, n)

	tstart := time.Now()

	// Use a HTTP payload so we can have one source implementation for tcp/http/tls
	buf := []byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
	rbuf := make([]byte, 1024)

	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			break
		}

		tconn := time.Now()
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
		latencies[i] = time.Since(tconn)

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
	tend := time.Now()
	elapsedSecs := float64(tend.Sub(tstart)) / float64(time.Second)
	stats.ActualConnRate = float64(n) / elapsedSecs
	stats.ActualReqRate = stats.ActualConnRate

	sort.Sort(ByDuration(latencies))
	stats.LatencyP50 = latencies[n / 2]
	stats.LatencyP90 = latencies[(n*9) / 10]
	stats.LatencyP99 = latencies[(n*99) / 100]

	return stats
}

func tlsSource(ctx context.Context, sinkPort int, n int, ratePerSec float64) SourceStats {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5000 * time.Millisecond},
		Config:    &tls.Config{InsecureSkipVerify: true},
	}
	return sourceLoop(ctx, sinkPort, dialer, n, ratePerSec)
}

func tcpSource(ctx context.Context, sinkPort int, n int, ratePerSec float64) SourceStats {
	dialer := &net.Dialer{Timeout: 5000 * time.Millisecond}
	return sourceLoop(ctx, sinkPort, dialer, n, ratePerSec)
}

func source(ctx context.Context, sinkPort int, mode string, n int, ratePerSec float64) SourceStats {
	switch mode {
	case "tls":
		return tlsSource(ctx, sinkPort, n, ratePerSec)
	case "tcp", "http":
		return tcpSource(ctx, sinkPort, n, ratePerSec)
	default:
		log.Fatalf("unknown mode %s", mode)
		return SourceStats{}
	}
}


func rrSourceLoop(ctx context.Context, sinkPort int, dialer ContextDialer, nRequests int, reqSize int) (stats SourceStats) {
	tstart := time.Now()
	latencies := make([]time.Duration, nRequests)
	// Use a HTTP payload so we can have one source implementation for tcp/http/tls
	buf := []byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n")
	padHdr := []byte("Pad :")
	if (len(buf) < reqSize - len(padHdr)) {
		// Pad the buffer with harmless header.
		buf = append(buf, []byte("Pad: ")...)
		buf = append(buf, bytes.Repeat([]byte("X"), reqSize - len(padHdr))...)
		buf = append(buf, []byte("\r\n")...)
	}
	buf = append(buf, "\r\n"...)

	rbuf := make([]byte, 8192)

	conn, err := dialer.DialContext(ctx, "tcp4", "127.0.0.1:"+strconv.Itoa(sinkPort))
	if err != nil {
		log.Printf("dial error: %v\n", err)
		stats.LastError = err.Error()
		stats.Errors++
		return
	}

	for i := 0; i < nRequests; i++ {
		if ctx.Err() != nil {
			break
		}
		treq := time.Now()
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
		latencies[i] = time.Since(treq)
	}
	conn.Close()

	tend := time.Now()
	elapsedSecs := float64(tend.Sub(tstart)) / float64(time.Second)
	stats.ActualReqRate = float64(nRequests) / elapsedSecs
	stats.ActualConnRate = 0
	sort.Sort(ByDuration(latencies))
	stats.LatencyP50 = latencies[nRequests / 2]
	stats.LatencyP90 = latencies[(nRequests * 9) / 10]
	stats.LatencyP99 = latencies[(nRequests * 99) / 100]
	return stats
}

func rrSource(ctx context.Context, sinkPort int, mode string, nRequests int, reqSize int) SourceStats {
	var dialer ContextDialer
	switch mode {
	case "tls":
		dialer = &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: 5000 * time.Millisecond},
			Config:    &tls.Config{InsecureSkipVerify: true},
		}
	case "tcp", "http":
		dialer = &net.Dialer{Timeout: 5000 * time.Millisecond}
	default:
		log.Fatalf("unknown mode %s", mode)
		return SourceStats{}
	}
	return rrSourceLoop(ctx, sinkPort, dialer, nRequests, reqSize)
}


func xAtoi(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		log.Fatal(err)
	}
	return n
}

func netperfSource(ctx context.Context, sinkPort int, mode string, nRequests int, reqSize int) (stats SourceStats) {
	cmd := exec.Command("netperf",
	                    "-Hlocalhost",
	                    "-l-" + strconv.Itoa(nRequests), // Yep, negative is number of requests and not time
	                    "-P0", // No header
	                    "-tTCP_RR",
	                    "--",
			    "-o", "elapsed_time,throughput,p50_latency,p90_latency,p99_latency")

	out, err := cmd.Output()
	if err != nil {
		log.Fatalf("netperf failed: %s", err)
	}
	reader := csv.NewReader(bytes.NewReader(out))

	rs, err := reader.Read()
	if err != nil {
		log.Fatalf("netperf csv output parse failed: %s", err)
	}

	stats.ActualConnRate = 0
	stats.ActualReqRate, err = strconv.ParseFloat(rs[1], 64)
	if err != nil {
		log.Fatalf("Failed to parse throughput: %s", err)
	}

	stats.LatencyP50 = time.Duration(xAtoi(rs[2])) * time.Microsecond
	stats.LatencyP90 = time.Duration(xAtoi(rs[3])) * time.Microsecond
	stats.LatencyP99 = time.Duration(xAtoi(rs[4])) * time.Microsecond

	return
}
