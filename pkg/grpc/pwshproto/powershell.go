// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package pwshproto

import (
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/api/powershellapi"
)

type MsgPowerShellEvent struct {
	Msg *powershellapi.MsgPowerShellEvent
}

func GetPowershellScriptBlock(event *MsgPowerShellEvent) *tetragon.PowershellScriptBlock {
	var fgsProcess, fgsParent *tetragon.Process
	process, parent := process.GetParentProcessInternal(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
	}
	if parent != nil {
		fgsParent = parent.UnsafeGetProcess()
	}
	fgsEvent := &tetragon.PowershellScriptBlock{
		Process:       fgsProcess,
		Parent:        fgsParent,
		ScriptPath:    event.Msg.ScriptPath,
		EngineVersion: event.Msg.EngineVersion,
		EnginePath:    event.Msg.PowerShellPath,
		Tid:           event.Msg.WinEvent.Tid,
		Uid:           event.Msg.WinEvent.Uid,
		CommandName:   event.Msg.CommandName,
		CommandLine:   event.Msg.CommandLine,
		Payload:       event.Msg.Payload,
	}
	return fgsEvent

}

func (msg *MsgPowerShellEvent) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	p := ev.GetProcess()
	return eventcache.HandleGenericInternal(ev, p.Pid.Value, nil, timestamp)
}

func (msg *MsgPowerShellEvent) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev, nil)
}

func (msg *MsgPowerShellEvent) Notify() bool {
	return true
}

func (msg *MsgPowerShellEvent) HandleMessage() *tetragon.GetEventsResponse {
	var res *tetragon.GetEventsResponse
	switch msg.Msg.Common.Op {
	case ops.MSG_OP_POWERSHELL_BLOCK:
		t := GetPowershellScriptBlock(msg)
		if t != nil {
			res = &tetragon.GetEventsResponse{
				Event: &tetragon.GetEventsResponse_PowershellScriptBlock{PowershellScriptBlock: t},
				Time:  ktime.ToProto(msg.Msg.Common.Ktime),
			}
		}
	default:
		logger.GetLogger().Warn("HandlePowerShellMessage: Unhandled event", "message", msg)
	}
	return res
}

func (msg *MsgPowerShellEvent) Cast(_ any) notify.Message {
	return &MsgPowerShellEvent{}
}
