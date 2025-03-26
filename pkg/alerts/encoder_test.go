//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package alerts

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/stretchr/testify/assert"
)

var exampleEvent = &tetragon.GetEventsResponse{
	Event: &tetragon.GetEventsResponse_ProcessExec{
		ProcessExec: &tetragon.ProcessExec{
			Process: &tetragon.Process{
				Binary:    "/usr/bin/curl",
				Arguments: "ebpf.io",
			},
		},
	},
	Time: &timestamppb.Timestamp{},
}

var exampleRule = &tetragon.AlertRuleMeta{
	Name:     "curl",
	Message:  "Curl is curling.",
	Tags:     []string{"network"},
	Severity: tetragon.AlertRuleMeta_CRITICAL,
}

var exampleAlert = &tetragon.Alert{
	Event: exampleEvent,
	Rule:  exampleRule,
}

type nopWriteCloser struct {
	io.Writer
}

func (w nopWriteCloser) Close() error {
	return nil
}

func normalizeJSON(s string) string {
	// Protobuf encoder is intentionally non-deterministic when it comes to
	// spaces after commas, so just normalize them for tests. See:
	// https://github.com/golang/protobuf/issues/1121
	return strings.ReplaceAll(s, ", \"", ",\"")
}

func TestJSONEncode(t *testing.T) {
	var buf bytes.Buffer
	wc := nopWriteCloser{&buf}

	// Create encoder, encode, check encoded JSON
	encoder := newJsonEncoder(wc)
	err := encoder.encode(exampleAlert)
	assert.NoError(t, err)

	expected := `{"event":{"process_exec":{"process":{"binary":"/usr/bin/curl","arguments":"ebpf.io"}},"time":"1970-01-01T00:00:00Z"},"rule":{"name":"curl","severity":"CRITICAL","message":"Curl is curling.","tags":["network"]}}`
	expected += "\n"
	assert.Equal(t, expected, normalizeJSON(buf.String()))
}

func TestJSONEncodeNoEvent(t *testing.T) {
	var buf bytes.Buffer
	wc := nopWriteCloser{&buf}

	// Create encoder, encode, check encoded JSON
	encoder := newJsonEncoder(wc)
	err := encoder.encode(&tetragon.Alert{Rule: exampleRule})
	assert.NoError(t, err)
	expected := `{"rule":{"name":"curl","severity":"CRITICAL","message":"Curl is curling.","tags":["network"]}}`
	expected += "\n"
	assert.Equal(t, expected, normalizeJSON(buf.String()))
}

func TestJSONEncodeEmpty(t *testing.T) {
	var buf bytes.Buffer
	wc := nopWriteCloser{&buf}

	// Create encoder, encode, check encoded JSON
	encoder := newJsonEncoder(wc)
	err := encoder.encode(&tetragon.Alert{})
	assert.NoError(t, err)
	expected := "{}\n"
	assert.Equal(t, expected, normalizeJSON(buf.String()))
}

func TestJSONEncodNil(t *testing.T) {
	var buf bytes.Buffer
	wc := nopWriteCloser{&buf}

	// Create encoder, encode, check encoded JSON
	encoder := newJsonEncoder(wc)
	err := encoder.encode(nil)
	assert.NoError(t, err)
	expected := "{}\n"
	assert.Equal(t, expected, normalizeJSON(buf.String()))
}

type errorWriteCloser struct{}

func (w errorWriteCloser) Write([]byte) (int, error) {
	return 0, errors.New("can't write")
}

func (w errorWriteCloser) Close() error { return nil }

func TestJSONEncodeWriteError(t *testing.T) {
	wc := errorWriteCloser{}
	encoder := newJsonEncoder(wc)

	err := encoder.encode(exampleAlert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "can't write")
}
