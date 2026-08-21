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
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"

	api "github.com/isovalent/hubble-fgs/pkg/api/tlsapi"
)

// sniExt builds the flv_sni buffer the BPF parser hands to userspace: the
// server_name extension data, then whatever the copy pulled in behind it. Its
// list covers exactly the name it carries.
func sniExt(nameType byte, nameLen int, name string, trailing []byte, flvLen uint8) api.FLV64 {
	return sniExtList(3+len(name), nameType, nameLen, name, trailing, flvLen)
}

// sniExtList takes the list length separately, so a case can declare a list
// shorter than the extension carrying it.
func sniExtList(listLen int, nameType byte, nameLen int, name string, trailing []byte, flvLen uint8) api.FLV64 {
	var flv api.FLV64
	flv.Value[0] = byte(listLen >> 8)
	flv.Value[1] = byte(listLen)
	flv.Value[2] = nameType
	flv.Value[3] = byte(nameLen >> 8)
	flv.Value[4] = byte(nameLen)
	copy(flv.Value[5:], name)
	copy(flv.Value[5+len(name):], trailing)
	flv.Length = flvLen
	return flv
}

func TestGetTLSSNI(t *testing.T) {
	// 12 bytes that can follow server_name on the wire: ec_point_formats,
	// renegotiation_info, and the first byte of the extension after them.
	adjacentExts := []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00}
	longName := strings.Repeat("a", 59)

	for _, tc := range []struct {
		name     string
		flv      api.FLV64
		wantType string
		wantName string
	}{
		{
			name:     "well formed",
			flv:      sniExt(0, 10, "foobar.baz", nil, 15),
			wantType: "host_name",
			wantName: "foobar.baz",
		},
		{
			name:     "name_len over-declared",
			flv:      sniExt(0, 48, "service-with-a-long-name.example.com", adjacentExts, 41),
			wantType: "host_name",
			wantName: "service-with-a-long-name.example.com",
		},
		{
			name:     "name_len 0xffff",
			flv:      sniExt(0, 0xffff, "foobar.baz", adjacentExts, 15),
			wantType: "host_name",
			wantName: "foobar.baz",
		},
		{
			name:     "captured length zero",
			flv:      sniExt(0, 10, "foobar.baz", nil, 0),
			wantType: "unknown",
			wantName: "",
		},
		{
			name:     "captured length below the extension header",
			flv:      sniExt(0, 10, "foobar.baz", nil, 4),
			wantType: "unknown",
			wantName: "",
		},
		{
			// A name that fills the buffer: the copy can capture at most 64
			// bytes, of which 59 are usable, so the FLV length over-reports.
			name:     "name fills the buffer",
			flv:      sniExt(0, 70, longName, nil, 75),
			wantType: "host_name",
			wantName: longName,
		},
		{
			name:     "non-UTF-8 inside a well-formed name",
			flv:      sniExt(0, 5, "ab\xffcd", nil, 10),
			wantType: "host_name",
			wantName: `ab\xFFcd`,
		},
		{
			name:     "unrecognised name type",
			flv:      sniExt(1, 10, "foobar.baz", nil, 15),
			wantType: "unknown",
			wantName: "foobar.baz",
		},
		{
			// The kernel captured 64 bytes of extension but the list covers
			// 13, so the captured length is not a tight enough bound on the
			// name.
			name:     "list shorter than the captured extension",
			flv:      sniExtList(13, 0, 50, "foobar.baz", adjacentExts, 64),
			wantType: "host_name",
			wantName: "foobar.baz",
		},
		{
			name:     "list length below the name entry header",
			flv:      sniExtList(0, 0, 40, "foobar.baz", nil, 15),
			wantType: "host_name",
			wantName: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotType, gotName := GetTLSSNI(&tc.flv)
			if gotType != tc.wantType {
				t.Errorf("GetTLSSNI() type = %q, expected %q", gotType, tc.wantType)
			}
			if gotName != tc.wantName {
				t.Errorf("GetTLSSNI() name = %q, expected %q", gotName, tc.wantName)
			}
			if !utf8.ValidString(gotName) {
				t.Errorf("GetTLSSNI() name = %q is not valid UTF-8", gotName)
			}
		})
	}
}

func FuzzGetTLSSNI(f *testing.F) {
	f.Add(uint8(15), []byte("\x00\x0d\x00\x00\x0afoobar.baz"))
	f.Add(uint8(41), []byte("\x00\x27\x00\x00\x30foobar.example.com\x00\x0b\x00\x02\x01\x00"))
	f.Add(uint8(0), []byte{})
	f.Add(uint8(255), []byte("\x00\xff\x00\xff\xff\xff\xff\xff"))

	f.Fuzz(func(t *testing.T, length uint8, data []byte) {
		var flv api.FLV64
		copy(flv.Value[:], data)
		flv.Length = length

		_, name := GetTLSSNI(&flv)
		if !utf8.ValidString(name) {
			t.Fatalf("GetTLSSNI() name = %q is not valid UTF-8", name)
		}
	})
}

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
