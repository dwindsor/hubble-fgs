// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package haclt

import (
	"time"

	"github.com/isovalent/hubble-fgs/pkg/cert"
	"github.com/isovalent/hubble-fgs/pkg/config"
	hav1 "github.com/isovalent/hubble-fgs/pkg/proto/ha/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

type Ha struct {
	addr       string
	caCert     string
	clientCert string
	clientKey  string
	skipAuth   bool
	// timeout
	conn   *grpc.ClientConn
	Client hav1.HaClient
}

// Retry policy for gRPC clients
// RetryableStatusCodes: UNAVAILABLE, UNKNOWN, RESOURCE_EXHAUSTED, FAILED_PRECONDITION, ABORTED, OUT_OF_RANGE
// See https://github.com/grpc/grpc/blob/master/doc/statuscodes.md for more information on status codes
var retryPolicy = `{
        "methodConfig": [{
          "name": [{"service": "proto.v1.Ha"}],
          "waitForReady": true,
          "retryPolicy": {
                  "MaxAttempts": 10,
                  "InitialBackoff": "0.01s",
                  "MaxBackoff": "3s",
                  "BackoffMultiplier": 3.0,
                  "RetryableStatusCodes": [ "UNAVAILABLE", "UNKNOWN", "RESOURCE_EXHAUSTED", "FAILED_PRECONDITION", "ABORTED", "OUT_OF_RANGE" ]
          }
        }]}`

var kacp = keepalive.ClientParameters{
	Time:                60 * time.Second, // send pings every 60 seconds if there is no activity
	Timeout:             3 * time.Second,  // wait 3 second for ping ack before considering the connection dead
	PermitWithoutStream: true,             // send pings even without active streams
}

var IsMutual bool

func (s *Ha) Connect(addr string, caCert string, clientCert string, clientKey string, skipAuth bool) error {
	s.addr = addr
	s.caCert = caCert
	s.clientCert = clientCert
	s.clientKey = clientKey
	s.skipAuth = skipAuth

	// Setting dial options based on skipAuth
	var opts []grpc.DialOption
	if s.skipAuth {
		opts = []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDefaultServiceConfig(retryPolicy), grpc.WithKeepaliveParams(kacp)}
	} else {
		creds, err := cert.GenClientCred(IsMutual, s.clientCert, s.clientKey)
		if err != nil {
			return err
		}
		opts = []grpc.DialOption{grpc.WithTransportCredentials(creds), grpc.WithDefaultServiceConfig(retryPolicy), grpc.WithKeepaliveParams(kacp)}
	}
	var err error
	s.conn, err = grpc.Dial(s.addr, opts...)
	if err != nil {
		return err
	}
	s.Client = hav1.NewHaClient(s.conn)
	return nil
}

func (s *Ha) Close() {
	if config.IsNil(s.conn) {
		return
	}
	s.conn.Close()
}

func (s *Ha) Reconnect() error {
	s.Close()
	creds, err := cert.GenClientCred(IsMutual, s.clientCert, s.clientKey)
	if err != nil {
		return err
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(creds), grpc.WithDefaultServiceConfig(retryPolicy)}
	s.conn, err = grpc.Dial(s.addr, opts...)
	if err != nil {
		return err
	}
	s.Client = hav1.NewHaClient(s.conn)
	return nil
}
