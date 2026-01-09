// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package testutils

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

var (
	str          string = "Hello, World!"
	httpResponse []byte = []byte(str)
)

// StartSimpleHTTPServer starts an HTTP server in a separate goroutine that
// replies to request with 128 null bytes. This registers a callback on cleanup
// to close the server.
func StartSimpleHTTPServer(t *testing.T, address string) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write(httpResponse)
	}))
	server.Listener = listener
	server.Start()
	t.Cleanup(func() {
		server.Close()
	})
}
