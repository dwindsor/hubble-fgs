package grpc

import (
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/ktime"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func (pm *ProcessManager) GetProcessKprobe(event *api.MsgGenericKprobeUnix) *fgs.ProcessKprobe {
	var fgsParent, fgsProcess *fgs.Process
	var fgsArgs []*fgs.KprobeArgument
	var fgsReturnArg *fgs.KprobeArgument

	process, parent := pm.getParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &fgs.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.process
	}
	process.mu.Lock()
	if pm.enableProcessCred {
		fgsProcess.Cap = reader.GetMsgCapabilities(event.Capabilities)
	}
	if pm.enableProcessNs {
		fgsProcess.Ns = reader.GetMsgNamespaces(event.Namespaces)
	}
	process.mu.Unlock()
	if parent == nil {
		fgsParent = &fgs.Process{}
	} else {
		fgsParent = parent.GetProcessCopy()
	}

	for _, arg := range event.Args {
		a := &fgs.KprobeArgument{}
		switch e := arg.(type) {
		case api.MsgGenericKprobeArgInt:
			a.Arg = &fgs.KprobeArgument_IntArg{IntArg: e.Value}
		case api.MsgGenericKprobeArgSize:
			a.Arg = &fgs.KprobeArgument_SizeArg{SizeArg: e.Value}
		case api.MsgGenericKprobeArgString:
			a.Arg = &fgs.KprobeArgument_StringArg{StringArg: e.Value}
		case api.MsgGenericKprobeArgSock:
			sockArg := &fgs.KprobeSock{
				Family:   reader.InetFamily(e.Family),
				Type:     reader.InetType(e.Type),
				Protocol: reader.InetProtocol(e.Protocol),
				Mark:     e.Mark,
				Priority: e.Priority,
			}
			a.Arg = &fgs.KprobeArgument_SockArg{SockArg: sockArg}
		case api.MsgGenericKprobeArgSkb:
			skbArg := &fgs.KprobeSkb{
				Hash:        e.Hash,
				Len:         e.Len,
				Priority:    e.Priority,
				Mark:        e.Mark,
				Saddr:       e.Saddr,
				Daddr:       e.Daddr,
				Sport:       e.Sport,
				Dport:       e.Dport,
				Proto:       e.Proto,
				SecPathLen:  e.SecPathLen,
				SecPathOlen: e.SecPathOLen,
			}
			a.Arg = &fgs.KprobeArgument_SkbArg{SkbArg: skbArg}
		case api.MsgGenericKprobeArgBytes:
			if e.OrigSize > uint64(len(e.Value)) {
				a.Arg = &fgs.KprobeArgument_TruncatedBytesArg{
					TruncatedBytesArg: &fgs.KprobeTruncatedBytes{
						OrigSize: e.OrigSize,
						BytesArg: e.Value,
					},
				}
			} else {
				a.Arg = &fgs.KprobeArgument_BytesArg{BytesArg: e.Value}
			}
		case api.MsgGenericKprobeArgFile:
			fileArg := &fgs.KprobeFile{
				Path:  reader.MarkUnresolvedPathComponents(reader.GenPath(e.Value), e.Flags),
				Flags: reader.FilePathFlagsToStr(e.Flags),
			}
			a.Arg = &fgs.KprobeArgument_FileArg{FileArg: fileArg}
		case api.MsgGenericKprobeArgPath:
			pathArg := &fgs.KprobePath{
				Path:  reader.MarkUnresolvedPathComponents(reader.GenPath(e.Value), e.Flags),
				Flags: reader.FilePathFlagsToStr(e.Flags),
			}
			a.Arg = &fgs.KprobeArgument_PathArg{PathArg: pathArg}
		default:
			pm.log.WithField("arg", e).Warnf("unexpected type: %T", e)
		}
		if arg.IsReturnArg() {
			fgsReturnArg = a
		} else {
			fgsArgs = append(fgsArgs, a)
		}
	}

	fgsEvent := &fgs.ProcessKprobe{
		Process:      fgsProcess,
		Parent:       fgsParent,
		FunctionName: event.FuncName,
		Args:         fgsArgs,
		Return:       fgsReturnArg,
		Action:       reader.KprobeAction(event.Action),
	}

	if pm.processCacheNeeded(fgsProcess) {
		pm.eventCache.add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}

	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}
	return fgsEvent
}

func (pm *ProcessManager) handleGenericKprobeMessage(msg *api.MsgGenericKprobeUnix) *fgs.GetEventsResponse {
	k := pm.GetProcessKprobe(msg)
	if k == nil {
		return nil
	}
	return &fgs.GetEventsResponse{
		Event:    &fgs.GetEventsResponse_ProcessKprobe{ProcessKprobe: k},
		NodeName: pm.nodeName,
		Time:     ktime.ToProto(msg.Common.Ktime),
	}
}

func (pm *ProcessManager) handleGenericTracepointMessage(msg *api.MsgGenericTracepointUnix) *fgs.GetEventsResponse {
	var fgsParent, fgsProcess *fgs.Process

	process, parent := pm.getParentProcessInternal(msg.ProcessKey.Pid, msg.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &fgs.Process{
			Pid:       &wrapperspb.UInt32Value{Value: msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(msg.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.process
	}
	if parent == nil {
		fgsParent = &fgs.Process{}
	} else {
		fgsParent = parent.GetProcessCopy()
	}

	var fgsArgs []*fgs.KprobeArgument
	for _, arg := range msg.Args {
		switch v := arg.(type) {
		case uint64:
			fgsArgs = append(fgsArgs, &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_SizeArg{
				SizeArg: v,
			}})
		case string:
			fgsArgs = append(fgsArgs, &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_StringArg{
				StringArg: v,
			}})

		case []byte:
			fgsArgs = append(fgsArgs, &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_BytesArg{
				BytesArg: v,
			}})

		default:
			logger.GetLogger().Warnf("handleGenericTracepointMessage: unhandled value: %+v (%T)", arg, arg)
		}
	}

	fgsEvent := &fgs.ProcessTracepoint{
		Process: fgsProcess,
		Parent:  fgsParent,
		Subsys:  msg.Subsys,
		Event:   msg.Event,
		Args:    fgsArgs,
	}

	if pm.processCacheNeeded(fgsProcess) {
		pm.eventCache.add(process, fgsEvent, ktime.ToProto(msg.Common.Ktime), msg)
		return nil
	}
	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}

	return &fgs.GetEventsResponse{
		Event:    &fgs.GetEventsResponse_ProcessTracepoint{ProcessTracepoint: fgsEvent},
		NodeName: pm.nodeName,
		Time:     ktime.ToProto(msg.Common.Ktime),
	}
}
