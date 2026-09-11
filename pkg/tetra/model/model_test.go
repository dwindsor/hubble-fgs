// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package model

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
)

func TestNewBrowserTreeServerUsesDedicatedMux(t *testing.T) {
	getter := &wrappedEvent{ApplicationModelEvent: &appModelV1.ApplicationModelEvent{}}
	srv := newBrowserTreeServer(context.Background(), getter)

	if srv.Addr != "localhost:3333" {
		t.Fatalf("expected browser tree server to bind to localhost:3333, got %q", srv.Addr)
	}
	if srv.Handler == nil {
		t.Fatal("browser tree server must have an explicit handler")
	}
	if srv.Handler == http.DefaultServeMux {
		t.Fatal("browser tree server must not use http.DefaultServeMux")
	}

	t.Run("serves UI", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/", nil)

		srv.Handler.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusOK {
			t.Fatalf("expected UI status %d, got %d", http.StatusOK, recorder.Code)
		}
		if !strings.Contains(recorder.Body.String(), "IPT_APP_MODEL_JSON") {
			t.Fatal("expected UI response to contain the application model marker")
		}
	})

	t.Run("does not serve default mux handlers", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/debug/pprof/heap", nil)

		srv.Handler.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusOK {
			t.Fatalf("expected UI status %d, got %d", http.StatusOK, recorder.Code)
		}
		if !strings.Contains(recorder.Body.String(), "IPT_APP_MODEL_JSON") {
			t.Fatal("expected request to be handled by the dedicated UI mux")
		}
	})
}
