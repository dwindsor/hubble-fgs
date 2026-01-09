// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package logutils

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/api/processapi"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
)

func FormatTupleSrc(common *processapi.MsgCommon, tuple *networkapi.MsgIPTuple) string {
	saddr := networkapi.GetIP(tuple.SAddr, common.Op, tuple.IPv6 != 0).String()
	return fmt.Sprintf("%s:%d", saddr, tuple.SPort)
}

func FormatTupleDst(common *processapi.MsgCommon, tuple *networkapi.MsgIPTuple) string {
	daddr := networkapi.GetIP(tuple.DAddr, common.Op, tuple.IPv6 != 0).String()
	return fmt.Sprintf("%s:%d", daddr, tuple.DPort)
}
