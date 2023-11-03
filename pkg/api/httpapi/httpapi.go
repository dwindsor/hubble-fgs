package httpapi

import (
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
)

const (
	HTTP_METHOD_POST = 1
	HTTP_METHOD_GET  = 2
)

type HttpKey struct {
	Tuple networkapi.MsgIPTuple
	Id    uint64
}

type MsgHttpUnix struct {
	Method               string
	Uri                  string
	Host                 string
	Protocol             string
	UserAgent            string
	ContentLength        string
	RespContentLength    string
	Code                 string
	Reason               string
	RespVersion          string
	RequestId            uint64
	Ktime                uint64
	Flags                uint32
	FlagsResponse        uint32
	TransferEncoding     string
	RespTransferEncoding string
}

type MsgHttp struct {
	Method uint32 `align:"method"`
	Flags  uint32 `align:"flags"`
	ReqId  uint64 `align:"send_cntr"`
	RespId uint64 `align:"recv_cntr"`
	Length uint64 `align:"url_length"`
}

type MsgHttpEvent struct {
	Common     processapi.MsgCommon    `align:"common"`
	Tuple      networkapi.MsgIPTuple   `align:"tuple"`
	ProcessKey processapi.MsgExecveKey `align:"execve"`
	Request    MsgHttp                 `align:"request"`
}
