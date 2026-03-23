// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package mock

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTxLog_WriteAndRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	tl := NewTxLog(path)
	if tl == nil {
		t.Fatal("expected non-nil TxLog")
	}
	defer tl.Close()

	tl.Log("startup", "", "", "")
	tl.Log("set", "System/foo", "bar", "")
	tl.Log("get", "System/foo", "", "")
	tl.Log("delete", "System/foo", "", "")

	entries, err := tl.ReadEntries("", "", "")
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(entries))
	}
	if entries[0].Action != "startup" {
		t.Errorf("expected action startup, got %q", entries[0].Action)
	}
	if entries[1].Path != "System/foo" || entries[1].Value != "bar" {
		t.Errorf("unexpected set entry: %+v", entries[1])
	}
}

func TestTxLog_FilterByExactPath(t *testing.T) {
	dir := t.TempDir()
	tl := NewTxLog(filepath.Join(dir, "test.log"))
	defer tl.Close()

	tl.Log("set", "System/foo/bar", "v1", "")
	tl.Log("set", "System/foo/baz", "v2", "")

	entries, err := tl.ReadEntries("System/foo/bar", "", "")
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Value != "v1" {
		t.Errorf("expected v1, got %q", entries[0].Value)
	}
}

func TestTxLog_FilterByPrefix(t *testing.T) {
	dir := t.TempDir()
	tl := NewTxLog(filepath.Join(dir, "test.log"))
	defer tl.Close()

	tl.Log("set", "System/sas-items/foo", "v1", "")
	tl.Log("set", "System/ch-items/bar", "v2", "")
	tl.Log("get", "System/sas-items/baz", "", "")

	entries, err := tl.ReadEntries("", "System/sas-items", "")
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
}

func TestTxLog_FilterByOperation(t *testing.T) {
	dir := t.TempDir()
	tl := NewTxLog(filepath.Join(dir, "test.log"))
	defer tl.Close()

	tl.Log("set", "System/foo", "v1", "")
	tl.Log("get", "System/foo", "", "")
	tl.Log("delete", "System/foo", "", "")
	tl.Log("SET", "System/bar", "v2", "") // mixed case action

	entries, err := tl.ReadEntries("", "", "set")
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	// "set" and "SET" both match case-insensitive
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
}

func TestTxLog_NilSafe(t *testing.T) {
	var tl *TxLog
	tl.Log("set", "path", "value", "")
	tl.Close()
	entries, err := tl.ReadEntries("", "", "")
	if err != nil {
		t.Errorf("unexpected error from nil TxLog: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected empty entries from nil TxLog")
	}
}

func TestTxLog_MissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.log")
	tl := &TxLog{path: path}
	entries, err := tl.ReadEntries("", "", "")
	if err != nil {
		t.Errorf("expected no error for missing file, got %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected empty entries for missing file")
	}
}

func TestTxLog_Timestamps(t *testing.T) {
	dir := t.TempDir()
	tl := NewTxLog(filepath.Join(dir, "test.log"))
	defer tl.Close()

	tl.Log("startup", "", "", "")
	entries, err := tl.ReadEntries("", "", "")
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
}

func TestTxLog_HandlerLogsOnSet(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "mock_gnmi.json")

	h := NewHandlerBuilder().
		WithPersistPath(persistPath).
		Build()
	defer h.Close()

	_ = h.SetAndNotify(nil, "device:/System/foo", "bar")

	logPath := filepath.Join(dir, "mock_gnmi.log")
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Fatalf("expected log file to exist at %s", logPath)
	}

	tl := &TxLog{path: logPath}
	entries, err := tl.ReadEntries("", "", "")
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}

	// Should have at least a startup entry and a set_notify entry
	var foundStartup, foundSet bool
	for _, e := range entries {
		if e.Action == "startup" {
			foundStartup = true
		}
		if e.Action == "set_notify" {
			foundSet = true
		}
	}
	if !foundStartup {
		t.Error("expected startup entry in log")
	}
	if !foundSet {
		t.Error("expected set_notify entry in log")
	}
}
