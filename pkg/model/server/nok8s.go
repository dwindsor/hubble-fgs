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

package server

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
)

type Server struct {
	tetragon.UnimplementedProcessModelServiceServer
	appModelV1.UnimplementedApplicationModelServiceServer
}

func DefaultNewServer() (*Server, error) {
	var err error
	if enterpriseOption.Config.EnableApplicationModel {
		err = fmt.Errorf("application server model not supported in nok8s builds")
	}
	return nil, err
}
