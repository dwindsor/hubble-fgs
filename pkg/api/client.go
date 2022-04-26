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
	"github.com/isovalent/hubble-fgs/pkg/api/calltraceapi"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/processapi"
	"github.com/isovalent/hubble-fgs/pkg/vtuple"
)

type MsgFGSReady struct{}

var MsgUnixSize uint32 = 640

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
	Common    processapi.MsgCommon      `align:"common"`
	Calltrace calltraceapi.MsgCalltrace `align:"calltrace"`
	Tuple     networkapi.MsgIPv4Tuple   `align:"tuple"`
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
