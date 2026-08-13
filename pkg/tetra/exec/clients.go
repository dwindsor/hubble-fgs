// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package exec

import (
	"context"

	"github.com/cilium/tetragon/cmd/tetra/common"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

type ApplicationModelClient struct {
	common.ConnWithContext
	Client appModelV1.ApplicationModelServiceClient
}

// NewApplicationModelClient return a connected client to a tetragon server, caller
// must call Close() on the client. On failure to connect, this function calls
// Fatal() thus stopping execution.
func NewApplicationModelClient(ctx context.Context) (*ApplicationModelClient, error) {
	ret, err := common.NewConnWithContext(ctx, common.ResolveServerAddress(), common.Timeout, "application_model.v1alpha.ApplicationModelService")
	if err != nil {
		return nil, err
	}

	c := &ApplicationModelClient{
		ConnWithContext: *ret,
		Client:          appModelV1.NewApplicationModelServiceClient(ret.Conn),
	}

	return c, nil
}

type ConnectedModelClient struct {
	common.ConnWithContext
	Client tetragon.ProcessModelServiceClient
}

// NewConnectedClient return a connected client to a tetragon server, caller
// must call Close() on the client. On failure to connect, this function calls
// Fatal() thus stopping execution.
func NewConnectedModelClient(ctx context.Context) (*ConnectedModelClient, error) {
	ret, err := common.NewConnWithContext(ctx, common.ResolveServerAddress(), common.Timeout, "tetragon.ProcessModelService")
	if err != nil {
		return nil, err
	}

	c := &ConnectedModelClient{
		ConnWithContext: *ret,
		Client:          tetragon.NewProcessModelServiceClient(ret.Conn),
	}

	return c, nil
}
