package dnsapi

import (
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
)

type MsgDns struct {
	Response      bool
	RCode         uint16
	AnswerTypes   []uint32
	QuestionTypes []uint32
	Names         []string
	IPs           []string
}

type MsgDnsUnix struct {
	Common     processapi.MsgCommon
	Tuple      networkapi.MsgIPTuple
	Return     int64
	ProcessKey processapi.MsgExecveKey
	SockCookie uint64
	Dns        MsgDns
}
