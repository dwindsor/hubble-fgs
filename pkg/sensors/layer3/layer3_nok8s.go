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

package layer3

import (
	"fmt"

	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
)

func enableBPFDnsPerPod(ipToIDMaps dnsparser.IPToIDMaps) error {
	return fmt.Errorf("cannot enable DNS per pod in a nok8s build")
}

func setupWorkloadID() error {
	return fmt.Errorf("cannot enable workloadID in a nok8s build")
}
