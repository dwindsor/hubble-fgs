package network

import (
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/stretchr/testify/assert"
)

func Test_TupleAddrString(t *testing.T) {
	tuple := networkapi.MsgIPTuple{
		SAddr: [2]uint64{16777343},
		DAddr: [2]uint64{16777343},
		DPort: 20480,
		SPort: 5334,
		IPv6:  0,
	}

	source, dest := TupleAddrString(&tuple, ops.MSG_OP_TCPSTATS)
	assert.Equal(t, "127.0.0.1:5334", source)
	assert.Equal(t, "127.0.0.1:80", dest)

	tuple = networkapi.MsgIPTuple{
		SAddr: [2]uint64{0, 72057594037927936},
		DAddr: [2]uint64{0, 72057594037927936},
		DPort: 20480,
		SPort: 5334,
		IPv6:  1,
	}

	source, dest = TupleAddrString(&tuple, ops.MSG_OP_TCPSTATS)
	assert.Equal(t, "[::1]:5334", source)
	assert.Equal(t, "[::1]:80", dest)
}
