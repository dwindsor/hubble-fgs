// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package rules

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cilium/tetragon/cmd/tetra/common"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

type ClientWithContext struct {
	conn          *grpc.ClientConn
	Client        tetragon.RuleServiceClient
	ctx           context.Context
	timeoutCancel context.CancelFunc
}

func (c ClientWithContext) Close() {
	c.conn.Close()
	c.timeoutCancel()
}

func NewClient() (*ClientWithContext, error) {
	c := &ClientWithContext{}
	c.ctx, c.timeoutCancel = context.WithTimeout(context.Background(), common.Timeout)

	var err error
	c.conn, err = grpc.NewClient(
		common.ResolveServerAddress(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithMaxCallAttempts(common.Retries+1), // maxAttempt includes the first call
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(common.MaxRecvMsgSize)),
	)
	if err != nil {
		return nil, err
	}
	c.Client = tetragon.NewRuleServiceClient(c.conn)

	return c, nil
}
