//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package sockops

import "github.com/isovalent/hubble-fgs/pkg/observer"

var (
	ObserverSockopsEstablished = observer.BpfLoadBuilder(
		"bpf_sockops.o",
		"sockops",
		"sockops",
		"sockops/fgs_sockops",
		"sockops_fgs_sockops",
		false,
		true,
		"sockops")
)
