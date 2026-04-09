// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !nok8s

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
			apiServer, token, ca, err := ParseServiceAccountAuth(tt.args.details)
			require.True(t, (err != nil) == tt.wantErr)
			require.Equal(t, tt.apiServer, apiServer)
			require.Equal(t, tt.token, token)
			require.Equal(t, tt.ca, ca)
		})
	}
}

func TestK8sConfigRetry(t *testing.T) {
	got := K8sConfigRetry()
	expected := -1 // the expected value returned by K8sConfigRetry
	require.Equal(t, expected, got)
}
