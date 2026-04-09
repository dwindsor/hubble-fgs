// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build nok8s

package netpol

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

var nok8sErr = errors.New("netpol not supported in nonk8s builds")

func AddFromYAML(data string) error {
	return fmt.Errorf("cannot add netpol: %w", nok8sErr)
}

func AddFromDir(dir string) error {
	if dir != "" {
		return fmt.Errorf("cannot add netpol from dir %s: %w", dir, nok8sErr)
	}
	return nil
}

func AddFromFile(path string) error {
	if path != "" {
		return fmt.Errorf("cannot add netpol from path %s: %w", path, nok8sErr)
	}
	return nil
}

type NetworkPolicyManager struct {
	ctx context.Context
	tetragon.UnimplementedNetworkPolicyServiceServer
}

func New(ctx context.Context) *NetworkPolicyManager {
	return &NetworkPolicyManager{
		ctx: ctx,
	}
}
