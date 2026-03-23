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
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
)

// TxEntry is a single transaction log entry, serialized as a JSON line.
type TxEntry struct {
	Timestamp string `json:"ts"`
	Action    string `json:"action"`
	Path      string `json:"path,omitempty"`
	Value     string `json:"value,omitempty"`
	Error     string `json:"error,omitempty"`
}

// TxLog is an append-only transaction log written as JSON lines.
type TxLog struct {
	mu   sync.Mutex
	file *os.File
	path string
}

// NewTxLog opens (or creates) the log file at the given path for append-only
// writing. Returns nil if the file cannot be opened.
func NewTxLog(path string) *TxLog {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		logger.GetLogger().Error("MockGnmiTxLog: failed to open log file", "path", path, "error", err)
		return nil
	}
	return &TxLog{file: f, path: path}
}

// Log appends a single JSON-line entry to the log.
// Any of path, value, errStr may be empty and will be omitted from the entry.
func (t *TxLog) Log(action, path, value, errStr string) {
	if t == nil {
		return
	}
	entry := TxEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Action:    action,
		Path:      path,
		Value:     compactJSON(value),
		Error:     errStr,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	data = append(data, '\n')

	t.mu.Lock()
	defer t.mu.Unlock()
	if _, err := t.file.Write(data); err != nil {
		logger.GetLogger().Error("MockGnmiTxLog: failed to write log entry", "error", err)
	}
}

// Close flushes and closes the underlying log file.
func (t *TxLog) Close() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.file != nil {
		_ = t.file.Sync()
		_ = t.file.Close()
		t.file = nil
	}
}

// Path returns the log file path.
func (t *TxLog) Path() string {
	if t == nil {
		return ""
	}
	return t.path
}

// ReadEntries reads all log entries from the file, optionally filtering by
// exact path match (pathExact), path prefix (pathPrefix), and action type
// (operation). Empty strings disable the corresponding filter.
// operation matching is case-insensitive.
func (t *TxLog) ReadEntries(pathExact, pathPrefix, operation string) ([]TxEntry, error) {
	if t == nil {
		return nil, nil
	}
	f, err := os.Open(t.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	opLower := strings.ToLower(operation)

	var entries []TxEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var e TxEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		if pathExact != "" && normalizePath(e.Path) != normalizePath(pathExact) {
			continue
		}
		if pathPrefix != "" && !strings.HasPrefix(normalizePath(e.Path), normalizePath(pathPrefix)) {
			continue
		}
		if opLower != "" && strings.ToLower(e.Action) != opLower {
			continue
		}
		entries = append(entries, e)
	}
	return entries, scanner.Err()
}

// compactJSON strips whitespace from s if it is valid JSON; otherwise returns s unchanged.
func compactJSON(s string) string {
	if s == "" {
		return s
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(s)); err == nil {
		return buf.String()
	}
	return s
}
