//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tlsmetrics

import (
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/stretchr/testify/assert"
)

func Test_GetNegotiatedVersion(t *testing.T) {
	version := GetNegotiatedVersion(&tetragon.Tls{NegotiatedVersion: "hello"})
	assert.Equal(t, "hello", version)
	// Test TLS 1.2 negotiated version
	version = GetNegotiatedVersion(&tetragon.Tls{ClientVersion: tlsVersion1_2, ServerVersion: tlsVersion1_2})
	assert.Equal(t, tlsVersion1_2, version)
	// Test TLS 1.1 negotiated versions
	version = GetNegotiatedVersion(&tetragon.Tls{ClientVersion: tlsVersion1_2, ServerVersion: tlsVersion1_1})
	assert.Equal(t, tlsVersion1_1, version)
	version = GetNegotiatedVersion(&tetragon.Tls{ClientVersion: tlsVersion1_1, ServerVersion: tlsVersion1_2})
	assert.Equal(t, tlsVersion1_1, version)
	version = GetNegotiatedVersion(&tetragon.Tls{ClientVersion: tlsVersion1_1, ServerVersion: tlsVersion1_1})
	assert.Equal(t, tlsVersion1_1, version)
	// Test TLS 1.0 negotiated versions
	version = GetNegotiatedVersion(&tetragon.Tls{ClientVersion: tlsVersion1_0, ServerVersion: tlsVersion1_2})
	assert.Equal(t, tlsVersion1_0, version)
	version = GetNegotiatedVersion(&tetragon.Tls{ClientVersion: tlsVersion1_2, ServerVersion: tlsVersion1_0})
	assert.Equal(t, tlsVersion1_0, version)
	version = GetNegotiatedVersion(&tetragon.Tls{ClientVersion: tlsVersion1_1, ServerVersion: tlsVersion1_0})
	assert.Equal(t, tlsVersion1_0, version)
	version = GetNegotiatedVersion(&tetragon.Tls{ClientVersion: tlsVersion1_0, ServerVersion: tlsVersion1_1})
	assert.Equal(t, tlsVersion1_0, version)
	version = GetNegotiatedVersion(&tetragon.Tls{ClientVersion: tlsVersion1_0, ServerVersion: tlsVersion1_0})
	assert.Equal(t, tlsVersion1_0, version)
}
