package kfreeapi

import (
	"github.com/cilium/tetragon/pkg/api/calltraceapi"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/vtuple"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
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
