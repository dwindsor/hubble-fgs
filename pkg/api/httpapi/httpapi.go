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

// In-order string representation of enum http_state from http.h
// This must be updated when adding new members to enum http_state
var HttpStateNames = []string{
	"skipped_method",
	"missing_context",
	"missing_process",
	"skipped_header",
}

// Total number of members in enum http_state from http.h
// This must be updated when adding new members to enum http_state
const HTTP_STATE_MAX = 4

type HttpStateStats struct {
	Count [HTTP_STATE_MAX]uint64 `align:"cnt"`
}
