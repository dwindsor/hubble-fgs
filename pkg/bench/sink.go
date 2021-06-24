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
	"log"
	"net"
	"net/http"
)

var (
	//go:embed cert.pem
	certPem []byte

	//go:embed key.pem
	keyPem []byte
)

func acceptAndClose(l net.Listener) {
	buf := make([]byte, 1024)
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		c.Read(buf)
		c.Write(buf)
		c.Close()
	}
}

func tcpListen(ctx context.Context) (net.Listener, int) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Listen: %s", err)
	}

	go func() {
		<-ctx.Done()
		l.Close()
	}()

	port := l.Addr().(*net.TCPAddr).Port
	return l, port
}

func tcpSink(ctx context.Context, sinkReady chan int) {
	l, port := tcpListen(ctx)
	sinkReady <- port
	acceptAndClose(l)
	l.Close()
}

func httpSink(ctx context.Context, sinkReady chan int) {
	l, port := tcpListen(ctx)
	sinkReady <- port

	buf := []byte("helloworld")

	http.Serve(l,
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				w.Write(buf)
			}),
	)
}

func tlsSink(ctx context.Context, sinkReady chan int) {
	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		log.Fatal(err)
	}

	l, port := tcpListen(ctx)
	l = tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{cert}})

	sinkReady <- port
	acceptAndClose(l)
	l.Close()
}

func sink(ctx context.Context, mode string, sinkReady chan int) {
	switch mode {
	case "http":
		httpSink(ctx, sinkReady)
	case "tls":
		tlsSink(ctx, sinkReady)
	case "tcp":
		tcpSink(ctx, sinkReady)
	default:
		log.Fatal("unknown mode")
	}
}
