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
