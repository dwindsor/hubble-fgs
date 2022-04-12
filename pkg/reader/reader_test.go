//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package reader

import (
	"strings"
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/api"
)

func TestDecodeCommonFlags(t *testing.T) {
	type args struct {
		flags uint32
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "empty",
			args: args{flags: 0},
			want: "",
		},
		{
			name: "multiple flags",
			// nolint We still want to support this even though it's deprecated
			args: args{flags: api.EventExecve | api.EventExecveAt | api.EventProcFS},
			want: "execve execveat procFS",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := strings.Join(DecodeCommonFlags(tt.args.flags), " "); got != tt.want {
				t.Errorf("DecodeCommonFlags() = %v, want %v", got, tt.want)
			}
		})
	}
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
