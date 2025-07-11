//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package testutils

import (
	"errors"
	"net/http"
	"testing"
)

// StartSimpleHTTPServer starts an HTTP server in a separate goroutine that
// replies to request with 128 null bytes. This registers a callback on cleanup
// to close the server.
func StartSimpleHTTPServer(t *testing.T, address string) {
	server := &http.Server{Addr: address, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(make([]byte, 128))
	})}
	go func() {
		err := server.ListenAndServe()
		if !errors.Is(err, http.ErrServerClosed) {
			panic(err) // can't call t.Fatal from another goroutine
		}
	}()
	t.Cleanup(func() {
		server.Close()
	})
}
