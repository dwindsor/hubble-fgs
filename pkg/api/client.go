//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package api

import (
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/processapi"
	"github.com/isovalent/hubble-fgs/pkg/vtuple"
)

type MsgFGSReady struct{}

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

type MsgCalltrace struct {
	Stack [16]uint64
	Ret   int32
}

var MsgUnixSize uint32 = 640

type MsgCredEvent struct {
	Common       processapi.MsgCommon       `align:"common"`
	ProcessKey   processapi.MsgExecveKey    `align:"current"`
	Capabilities processapi.MsgCapabilities `align:"caps"`
}

type MsgCredEventUnix = MsgCredEvent

type MsgTestEvent struct {
	Common processapi.MsgCommon `align:"common"`
	Arg0   uint64               `align:"arg0"`
	Arg1   uint64               `align:"arg1"`
	Arg2   uint64               `align:"arg2"`
	Arg3   uint64               `align:"arg3"`
}

type MsgTestEventUnix = MsgTestEvent

type SensorStatus struct {
	Name    string
	Enabled bool
}

type MsgKfreeSkb struct {
	Common    processapi.MsgCommon    `align:"common"`
	Calltrace MsgCalltrace            `align:"calltrace"`
	Tuple     networkapi.MsgIPv4Tuple `align:"tuple"`
}

type StackAddr struct {
	Addr   uint64
	Symbol string
}

type MsgKfreeSkbUnix struct {
	Common    processapi.MsgCommon
	Calltrace []StackAddr
	Tuple     vtuple.Impl
}
