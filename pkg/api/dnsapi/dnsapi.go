package dnsapi

import (
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/processapi"
)

type MsgDns struct {
	Response      bool
	RCode         uint16
	AnswerTypes   []uint32
	QuestionTypes []uint32
	Names         []string
	IPs           []string
}

type MsgIPv4DnsUnix struct {
	Common     processapi.MsgCommon
	Tuple      networkapi.MsgIPv4Tuple
	Return     int64
	ProcessKey processapi.MsgExecveKey
	SockCookie uint64
	Dns        MsgDns
}
