package kfreeapi

import (
	"github.com/isovalent/hubble-fgs/pkg/api/calltraceapi"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/processapi"
	"github.com/isovalent/hubble-fgs/pkg/vtuple"
)

type StackAddr struct {
	Addr   uint64
	Symbol string
}

type MsgKfreeSkb struct {
	Common    processapi.MsgCommon      `align:"common"`
	Calltrace calltraceapi.MsgCalltrace `align:"calltrace"`
	Tuple     networkapi.MsgIPv4Tuple   `align:"tuple"`
}

type MsgKfreeSkbUnix struct {
	Common    processapi.MsgCommon
	Calltrace []calltraceapi.StackAddr
	Tuple     vtuple.Impl
}
