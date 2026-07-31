// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package getalerts

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cilium/tetragon/cmd/tetra/common"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

// retryPolicy returns a gRPC service config retry policy targeting
// tetragon.AlertService. common.RetryPolicy targets FineGuidanceSensors
// only; without a matching policy WithMaxCallAttempts is a no-op.
func retryPolicy(retries int) string {
	if retries < 0 {
		return "{}"
	}
	maxAttempt := retries + 1
	return fmt.Sprintf(`{
	"methodConfig": [{
	  "name": [{"service": "tetragon.AlertService"}],
	  "retryPolicy": {
		  "MaxAttempts": %d,
		  "InitialBackoff": "1s",
		  "MaxBackoff": "3600s",
		  "BackoffMultiplier": 2,
		  "RetryableStatusCodes": [ "UNAVAILABLE" ]
	  }
	}]}`, maxAttempt)
}

type ClientWithContext struct {
	conn         *grpc.ClientConn
	Client       tetragon.AlertServiceClient
	Ctx          context.Context
	signalCancel context.CancelFunc
}

func (c *ClientWithContext) Close() {
	c.conn.Close()
	c.signalCancel()
}

func NewClient() (*ClientWithContext, error) {
	c := &ClientWithContext{}
	c.Ctx, c.signalCancel = signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	var err error
	c.conn, err = grpc.NewClient(
		common.ResolveServerAddress(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultServiceConfig(retryPolicy(common.Retries)),
		grpc.WithMaxCallAttempts(common.Retries+1),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(common.MaxRecvMsgSize)),
	)
	if err != nil {
		return nil, err
	}
	c.Client = tetragon.NewAlertServiceClient(c.conn)

	return c, nil
}
