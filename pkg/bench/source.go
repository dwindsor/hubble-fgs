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
	"log"
	"net"
	"strconv"
	"time"

	"golang.org/x/time/rate"
)

type SourceStats struct {
	ActualRate float64
	Errors     int64
	LastError  string
}

type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func sourceLoop(ctx context.Context, sinkPort int, dialer ContextDialer, n int, ratePerSec float64) SourceStats {
	limiter := rate.NewLimiter(rate.Limit(ratePerSec), 5 /* burst */)
	var stats SourceStats

	tstart := time.Now()

	// Use a HTTP payload so we can have one source implementation for tcp/http/tls
	buf := []byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
	rbuf := make([]byte, 1024)

	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			break
		}

		conn, err := dialer.DialContext(ctx, "tcp4", "127.0.0.1:"+strconv.Itoa(sinkPort))
		if err != nil {
			stats.LastError = err.Error()
			stats.Errors++
			continue
		}
		_, err = conn.Write(buf)
		if err != nil {
			stats.LastError = err.Error()
			stats.Errors++
			continue
		}
		_, err = conn.Read(rbuf)
		if err != nil {
			stats.LastError = err.Error()
			stats.Errors++
			continue
		}
		conn.Close()
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
	stats.ActualRate = float64(n) / elapsedSecs
	return stats
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
