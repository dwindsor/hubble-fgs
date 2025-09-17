// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package conf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_parseServiceAccountAuth(t *testing.T) {
	type args struct {
		details string
	}
	tests := []struct {
		name      string
		args      args
		apiServer string
		token     string
		ca        string
		wantErr   bool
	}{
		{
			name: "valid input with all fields",
			args: args{
				details: "aHR0cDovLzEyNy4wLjAuMXx0b2tlbl8xfGNhXzE=",
			},
			apiServer: "http://127.0.0.1",
			token:     "token_1",
			ca:        "ca_1",
			wantErr:   false,
		},
		{
			name: "valid input without CA",
			args: args{
				details: "aHR0cDovLzEyNy4wLjAuMXx0b2tlbl8xfA==",
			},
			apiServer: "http://127.0.0.1",
			token:     "token_1",
			ca:        "",
			wantErr:   false,
		},
		{
			name: "invalid base64 input",
			args: args{
				details: "testing",
			},
			wantErr: true,
		},
		{
			name: "more than 4 fields",
			args: args{
				details: "aHR0cDovLzEyNy4wLjAuMXx0b2tlbl8xfGNhXzF8ZXh0cmE=",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiServer, token, ca, err := parseServiceAccountAuth(tt.args.details)
			require.True(t, (err != nil) == tt.wantErr)
			require.Equal(t, tt.apiServer, apiServer)
			require.Equal(t, tt.token, token)
			require.Equal(t, tt.ca, ca)
		})
	}
}
