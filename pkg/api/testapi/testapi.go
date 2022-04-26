package testapi

import "github.com/isovalent/hubble-fgs/pkg/api/processapi"

type MsgTestEvent struct {
	Common processapi.MsgCommon `align:"common"`
	Arg0   uint64               `align:"arg0"`
	Arg1   uint64               `align:"arg1"`
	Arg2   uint64               `align:"arg2"`
	Arg3   uint64               `align:"arg3"`
}

type MsgTestEventUnix = MsgTestEvent
