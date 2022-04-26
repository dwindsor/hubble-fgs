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
