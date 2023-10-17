//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package sandbox

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/reader/notify"

	"google.golang.org/protobuf/types/known/wrapperspb"
)

// implement the Message interface for sandbox events

var (
	nodeName = node.GetNodeNameForExport()
)

type MsgRawSyscall struct {
	// tpMsg is the original message
	tpMsg *tracing.MsgGenericTracepointUnix
	// xlateFn translates the original tracepoint event to a ProcessSandboxSyscall event
	xlateFn func(orig *tracing.MsgGenericTracepointUnix, ev *tetragon.ProcessSandboxSyscall) error
}

func NewMsgRawSyscall(
	m *tracing.MsgGenericTracepointUnix,
	xlateFn func(orig *tracing.MsgGenericTracepointUnix, ev *tetragon.ProcessSandboxSyscall) error,
) *MsgRawSyscall {
	return &MsgRawSyscall{
		tpMsg:   m,
		xlateFn: xlateFn,
	}
}

func (msg *MsgRawSyscall) RetryInternal(
	ev notify.Event, timestamp uint64,
) (*process.ProcessInternal, error) {
	return msg.tpMsg.RetryInternal(ev, timestamp)
}

func (msg *MsgRawSyscall) Retry(
	internal *process.ProcessInternal, ev notify.Event,
) error {
	return msg.tpMsg.Retry(internal, ev)
}

func (msg *MsgRawSyscall) Notify() bool {
	return msg.tpMsg.Notify()
}

func (msg *MsgRawSyscall) Cast(o interface{}) notify.Message {
	t := o.(MsgRawSyscall)
	return &t
}

func (msg *MsgRawSyscall) HandleMessage() *tetragon.GetEventsResponse {
	var tetragonParent, tetragonProcess *tetragon.Process

	proc, parent := process.GetParentProcessInternal(msg.tpMsg.Msg.ProcessKey.Pid, msg.tpMsg.Msg.ProcessKey.Ktime)
	if proc == nil {
		tetragonProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: msg.tpMsg.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(msg.tpMsg.Msg.ProcessKey.Ktime),
		}
	} else {
		tetragonProcess = proc.UnsafeGetProcess()
	}
	if parent != nil {
		tetragonParent = parent.UnsafeGetProcess()
	}

	tetragonEvent := &tetragon.ProcessSandboxSyscall{
		Process: tetragonProcess,
		Parent:  tetragonParent,
	}

	err := msg.Translate(tetragonEvent)
	if err != nil {
		logger.GetLogger().Warn("unexpected error in handling sandbox event: %w")
		return nil
	}

	if ec := eventcache.Get(); ec != nil &&
		(ec.Needed(tetragonProcess) ||
			(tetragonProcess.Pid.Value > 1 && ec.Needed(tetragonParent))) {
		ec.Add(nil, tetragonEvent, msg.tpMsg.Msg.Common.Ktime, msg.tpMsg.Msg.ProcessKey.Ktime, msg)
		return nil
	}

	if proc != nil {
		// At tracepoints we report the per thread fields, so take a copy
		// of the thread leader from the cache then update the corresponding
		// per thread fields.
		//
		// The cost to get this is relatively high because it requires a
		// deep copy of all the fields of the thread leader from the cache in
		// order to safely modify them, to not corrupt gRPC streams.
		tetragonEvent.Process = proc.GetProcessCopy()
		process.UpdateEventProcessTid(tetragonEvent.Process, &msg.tpMsg.Msg.Tid)
	}

	return &tetragon.GetEventsResponse{
		Event:    &tetragon.GetEventsResponse_ProcessSandboxSyscall{ProcessSandboxSyscall: tetragonEvent},
		NodeName: nodeName,
		Time:     ktime.ToProto(msg.tpMsg.Msg.Common.Ktime),
	}
}

func (msg *MsgRawSyscall) Translate(ev *tetragon.ProcessSandboxSyscall) error {
	return msg.xlateFn(msg.tpMsg, ev)
}
