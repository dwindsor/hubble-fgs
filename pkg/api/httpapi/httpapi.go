// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package httpapi

import (
	"net/http"

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
	Common        processapi.MsgCommon    `align:"common"`
	SocketCookie  uint64                  `align:"socket_cookie"`
	SocketVersion uint64                  `align:"socket_version"`
	Tuple         networkapi.MsgIPTuple   `align:"tuple"`
	ProcessKey    processapi.MsgExecveKey `align:"execve"`
	Request       MsgHttp                 `align:"request"`
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

// All status codes defined in net/http, based on
// https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
var KnownHTTPStatusCodes = []int{
	http.StatusContinue,
	http.StatusSwitchingProtocols,
	http.StatusProcessing,
	http.StatusEarlyHints,

	http.StatusOK,
	http.StatusCreated,
	http.StatusAccepted,
	http.StatusNonAuthoritativeInfo,
	http.StatusNoContent,
	http.StatusResetContent,
	http.StatusPartialContent,
	http.StatusMultiStatus,
	http.StatusAlreadyReported,
	http.StatusIMUsed,

	http.StatusMultipleChoices,
	http.StatusMovedPermanently,
	http.StatusFound,
	http.StatusSeeOther,
	http.StatusNotModified,
	http.StatusUseProxy,

	http.StatusTemporaryRedirect,
	http.StatusPermanentRedirect,

	http.StatusBadRequest,
	http.StatusUnauthorized,
	http.StatusPaymentRequired,
	http.StatusForbidden,
	http.StatusNotFound,
	http.StatusMethodNotAllowed,
	http.StatusNotAcceptable,
	http.StatusProxyAuthRequired,
	http.StatusRequestTimeout,
	http.StatusConflict,
	http.StatusGone,
	http.StatusLengthRequired,
	http.StatusPreconditionFailed,
	http.StatusRequestEntityTooLarge,
	http.StatusRequestURITooLong,
	http.StatusUnsupportedMediaType,
	http.StatusRequestedRangeNotSatisfiable,
	http.StatusExpectationFailed,
	http.StatusTeapot,
	http.StatusMisdirectedRequest,
	http.StatusUnprocessableEntity,
	http.StatusLocked,
	http.StatusFailedDependency,
	http.StatusTooEarly,
	http.StatusUpgradeRequired,
	http.StatusPreconditionRequired,
	http.StatusTooManyRequests,
	http.StatusRequestHeaderFieldsTooLarge,
	http.StatusUnavailableForLegalReasons,

	http.StatusInternalServerError,
	http.StatusNotImplemented,
	http.StatusBadGateway,
	http.StatusServiceUnavailable,
	http.StatusGatewayTimeout,
	http.StatusHTTPVersionNotSupported,
	http.StatusVariantAlsoNegotiates,
	http.StatusInsufficientStorage,
	http.StatusLoopDetected,
	http.StatusNotExtended,
	http.StatusNetworkAuthenticationRequired,
}
