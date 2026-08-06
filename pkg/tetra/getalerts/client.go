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

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
)

type ClientWithContext struct {
	common.ConnWithContext
	Client tetragon.AlertServiceClient
}

func NewClient() (*ClientWithContext, error) {
	ret, err := common.NewConnWithContext(context.Background(), common.ResolveServerAddress(), common.Timeout, "tetragon.AlertService")
	if err != nil {
		return nil, err
	}

	c := &ClientWithContext{
		ConnWithContext: *ret,
		Client:          tetragon.NewAlertServiceClient(ret.Conn),
	}

	return c, nil
}
