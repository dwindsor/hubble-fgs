// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein, and the intellectual and technical
// concepts contained herein, are proprietary to Isovalent Inc. and its suppliers.

package javaattach

import (
	"io"
	"net"
	"strings"
	"testing"
)

func TestSendLoadRequest(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	serverErr := make(chan error, 1)
	go func() {
		defer server.Close()
		want := "1\x00load\x00/usr/lib/libtetragon-jvm-patch.so\x00true\x00/tmp/manifest\x00"
		request := make([]byte, len(want))
		if _, err := io.ReadFull(server, request); err != nil {
			serverErr <- err
			return
		}
		if string(request) != want {
			serverErr <- &requestError{got: string(request), want: want}
			return
		}
		_, err := io.WriteString(server, "0\n")
		serverErr <- err
	}()

	err := sendLoadRequest(client, "/usr/lib/libtetragon-jvm-patch.so", "/tmp/manifest")
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestParseNamespacePID(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  string
		hostPID int
		want    int
	}{
		{name: "container pid", status: "Name:\tjava\nNSpid:\t9478\t18\n", hostPID: 9478, want: 18},
		{name: "host pid", status: "Name:\tjava\nNSpid:\t42\n", hostPID: 42, want: 42},
		{name: "legacy kernel", status: "Name:\tjava\n", hostPID: 42, want: 42},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseNamespacePID([]byte(tc.status), tc.hostPID)
			if err != nil || got != tc.want {
				t.Fatalf("parseNamespacePID() = %d, %v; want %d", got, err, tc.want)
			}
		})
	}
	if _, err := parseNamespacePID([]byte("NSpid:\n"), 42); err == nil {
		t.Fatal("empty NSpid field accepted")
	}
}

func TestSendLoadRequestReturnsAgentFailure(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		defer server.Close()
		request := "1\x00load\x00/usr/lib/agent.so\x00true\x00/tmp/manifest\x00"
		_, _ = io.CopyN(io.Discard, server, int64(len(request)))
		_, _ = io.WriteString(server, "1\nJVMTI_ERROR_UNMODIFIABLE_CLASS")
	}()
	err := sendLoadRequest(client, "/usr/lib/agent.so", "/tmp/manifest")
	if err == nil || !strings.Contains(err.Error(), "status 1") {
		t.Fatalf("expected attach failure, got %v", err)
	}
}

type requestError struct{ got, want string }

func (e *requestError) Error() string { return "request mismatch" }
