// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tls

import (
	"testing"

	"github.com/stretchr/testify/assert"

	api "github.com/isovalent/hubble-fgs/pkg/api/tlsapi"
)

func TestGetTLSSupportedVersions(t *testing.T) {
	// Test empty versions
	s := GetTLSSupportedVersions(&api.FLV16{}, false)
	if s != "" {
		t.Errorf("GetTLSSupportedVersions([], false) = %q, expected \"\"", s)
	}

	// Test short lengths
	s = GetTLSSupportedVersions(
		&api.FLV16{
			Length: 3,
			Value:  [16]uint8{1, byte(api.TLSVersion13 & 0xff), byte(api.TLSVersion13 >> 8)},
		},
		true,
	)
	if s != "" {
		t.Errorf("GetTLSSupportedVersions([2, TLS13], true) = %q, expected \"\"", s)
	}

	// Test single version
	s = GetTLSSupportedVersions(
		&api.FLV16{
			Length: 3,
			Value:  [16]uint8{2, byte(api.TLSVersion13 & 0xff), byte(api.TLSVersion13 >> 8)},
		},
		true,
	)
	ex := "TLS1.3"
	if s != ex {
		t.Errorf("GetTLSSupportedVersions([2, TLS13], true) = %q, expected \"%s\"", s, ex)
	}

	// Test graceful handling of length overflow
	s = GetTLSSupportedVersions(
		&api.FLV16{
			Length: 3,
			Value:  [16]uint8{3, byte(api.TLSVersion13 & 0xff), byte(api.TLSVersion13 >> 8)},
		},
		true,
	)
	if s != ex {
		t.Errorf("GetTLSSupportedVersions([100], true) = %q, expected %q", s, ex)
	}

	// Test lengthless single version
	s = GetTLSSupportedVersions(
		&api.FLV16{
			Length: 2,
			Value:  [16]uint8{byte(api.TLSVersion13 & 0xff), byte(api.TLSVersion13 >> 8)},
		},
		false,
	)
	ex = "TLS1.3"
	if s != ex {
		t.Errorf("GetTLSSupportedVersions([TLS13], true) = %q, expected %q", s, ex)
	}

	// Test multiple versions
	s = GetTLSSupportedVersions(
		&api.FLV16{
			Length: 5,
			Value: [16]uint8{4,
				byte(api.TLSVersion13 & 0xff), byte(api.TLSVersion13 >> 8),
				byte(api.TLSVersion10 & 0xff), byte(api.TLSVersion10 >> 8),
			},
		},
		true,
	)
	ex = "TLS1.3 TLS1.0"
	if s != ex {
		t.Errorf("GetTLSSupportedVersions([4, TLS13, TLS10], true) = %s, expected \"%s\"", s, ex)
	}

	// Test unknown versions
	s = GetTLSSupportedVersions(
		&api.FLV16{
			Length: 5,
			Value:  [16]uint8{4, 0x01, 0x00, 0x02, 0x00},
		},
		true,
	)
	ex = "unknown(1) unknown(2)"
	if s != ex {
		t.Errorf("GetTLSSupportedVersions([4, TLS13, TLS10], true) = %s, expected \"%s\"", s, ex)
	}
}

func Test_GetNegotiatedVersion(t *testing.T) {
	version := GetTLSNegotitatedVersion12("unknown(1337)", api.TLSVersion1_2)
	assert.Equal(t, "unknown(1337)", version)
	version = GetTLSNegotitatedVersion12(api.TLSVersion1_1, "unknown(2112)")
	assert.Equal(t, "unknown(2112)", version)
	// Test TLS 1.2 negotiated version
	version = GetTLSNegotitatedVersion12(api.TLSVersion1_2, api.TLSVersion1_2)
	assert.Equal(t, api.TLSVersion1_2, version)
	// Test TLS 1.1 negotiated versions
	version = GetTLSNegotitatedVersion12(api.TLSVersion1_2, api.TLSVersion1_1)
	assert.Equal(t, api.TLSVersion1_1, version)
	version = GetTLSNegotitatedVersion12(api.TLSVersion1_1, api.TLSVersion1_2)
	assert.Equal(t, api.TLSVersion1_1, version)
	version = GetTLSNegotitatedVersion12(api.TLSVersion1_1, api.TLSVersion1_1)
	assert.Equal(t, api.TLSVersion1_1, version)
	// Test TLS 1.0 negotiated versions
	version = GetTLSNegotitatedVersion12(api.TLSVersion1_0, api.TLSVersion1_2)
	assert.Equal(t, api.TLSVersion1_0, version)
	version = GetTLSNegotitatedVersion12(api.TLSVersion1_2, api.TLSVersion1_0)
	assert.Equal(t, api.TLSVersion1_0, version)
	version = GetTLSNegotitatedVersion12(api.TLSVersion1_1, api.TLSVersion1_0)
	assert.Equal(t, api.TLSVersion1_0, version)
	version = GetTLSNegotitatedVersion12(api.TLSVersion1_0, api.TLSVersion1_1)
	assert.Equal(t, api.TLSVersion1_0, version)
	version = GetTLSNegotitatedVersion12(api.TLSVersion1_0, api.TLSVersion1_0)
	assert.Equal(t, api.TLSVersion1_0, version)
}
