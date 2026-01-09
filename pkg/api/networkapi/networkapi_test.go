// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package networkapi

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/isovalent/hubble-fgs/pkg/api/ops"
)

func Test_TupleAddrString(t *testing.T) {
	tuple := MsgIPTuple{
		SAddr: [2]uint64{16777343},
		DAddr: [2]uint64{16777343},
		DPort: 80,
		SPort: 5334,
		IPv6:  0,
	}

	source, dest := TupleAddrString(&tuple, ops.MSG_OP_TCPSTATS)
	assert.Equal(t, "127.0.0.1:5334", source)
	assert.Equal(t, "127.0.0.1:80", dest)

	tuple = MsgIPTuple{
		SAddr: [2]uint64{0, 72057594037927936},
		DAddr: [2]uint64{0, 72057594037927936},
		DPort: 80,
		SPort: 5334,
		IPv6:  1,
	}

	source, dest = TupleAddrString(&tuple, ops.MSG_OP_TCPSTATS)
	assert.Equal(t, "[::1]:5334", source)
	assert.Equal(t, "[::1]:80", dest)
}
