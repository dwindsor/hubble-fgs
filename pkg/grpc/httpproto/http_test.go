// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package httpproto

import (
	"testing"
	"unicode/utf8"

	"github.com/cilium/tetragon/pkg/option"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/isovalent/hubble-fgs/pkg/api/httpapi"
)

// GetHttp is the sole conversion point for HTTP/1 and HTTP/2 events, and the
// HTTP/2 decode path fills these header fields with raw octets that need not be
// valid UTF-8. proto3 strings must be valid UTF-8, so an unsanitized field
// makes proto.Marshal and protojson.Marshal reject the whole event. Feeding
// GetHttp a request whose header fields carry invalid bytes checks that the
// returned event still marshals.
func TestGetHttpSanitizesInvalidUTF8(t *testing.T) {
	orig := option.Config.DisableProcessCache
	option.Config.DisableProcessCache = true
	t.Cleanup(func() { option.Config.DisableProcessCache = orig })

	event := &MsgHttpEventUnix{
		Msg: &httpapi.MsgHttpEvent{},
		Request: httpapi.MsgHttpUnix{
			Method:    "GET\xff",
			Uri:       "/path-\xff\xfe",
			Host:      "h2-\xff.example",
			UserAgent: "agent-\xff",
			Code:      "200",
		},
	}

	got := GetHttp(event)
	require.NotNil(t, got)
	require.NotNil(t, got.Http.Request)

	req := got.Http.Request
	for name, value := range map[string]string{
		"Method": req.Method,
		"Uri":    req.Uri,
		"Host":   req.Host,
		"Agent":  req.Agent,
	} {
		require.Truef(t, utf8.ValidString(value), "%s is not valid UTF-8: %q", name, value)
	}

	_, err := proto.Marshal(got)
	require.NoError(t, err, "proto binary marshal must accept the sanitized event")

	_, err = protojson.Marshal(got)
	require.NoError(t, err, "protojson marshal must accept the sanitized event")
}
