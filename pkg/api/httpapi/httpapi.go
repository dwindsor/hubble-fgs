package httpapi

import (
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/processapi"
)

const (
	HTTP_METHOD_POST = 1
	HTTP_METHOD_GET  = 2
)

type HttpKey struct {
	Tuple networkapi.MsgIPv4Tuple
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
	Method uint32
	Flags  uint32
	ReqId  uint64
	RespId uint64
	Url    [1024]byte
	Pad1   uint32
	Pad2   uint32
	Pad3   uint32
}

type MsgHttpEventUnix struct {
	Common     processapi.MsgCommon
	Tuple      networkapi.MsgIPv4Tuple
	ProcessKey processapi.MsgExecveKey
	Request    MsgHttpUnix
}

type MsgHttpEvent struct {
	Common     processapi.MsgCommon
	Tuple      networkapi.MsgIPv4Tuple
	ProcessKey processapi.MsgExecveKey
	Request    MsgHttp
}
