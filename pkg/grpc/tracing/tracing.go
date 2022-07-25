package tracing

import (
	"github.com/cilium/hubble/pkg/cilium"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/api/tracingapi"
	api "github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/caps"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/reader/path"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/reader/network"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	nodeName = node.GetNodeNameForExport()
)

type Grpc struct {
	dnsCache          *dns.Cache
	ciliumState       *cilium.State
	eventCache        *eventcache.Cache
	enableCilium      bool
	enableProcessCred bool
	enableProcessNs   bool
}

func kprobeAction(act uint64) tetragon.KprobeAction {
	switch act {
	case tracingapi.ActionPost:
		return tetragon.KprobeAction_KPROBE_ACTION_POST
	case tracingapi.ActionFollowFd:
		return tetragon.KprobeAction_KPROBE_ACTION_FOLLOWFD
	case tracingapi.ActionSigKill:
		return tetragon.KprobeAction_KPROBE_ACTION_SIGKILL
	case tracingapi.ActionUnfollowFd:
		return tetragon.KprobeAction_KPROBE_ACTION_UNFOLLOWFD
	case tracingapi.ActionOverride:
		return tetragon.KprobeAction_KPROBE_ACTION_OVERRIDE
	case tracingapi.ActionCopyFd:
		return tetragon.KprobeAction_KPROBE_ACTION_COPYFD
	default:
		return tetragon.KprobeAction_KPROBE_ACTION_UNKNOWN
	}
}

func (t *Grpc) GetProcessKprobe(event *api.MsgGenericKprobeUnix) *tetragon.ProcessKprobe {
	var fgsParent, fgsProcess *tetragon.Process
	var fgsArgs []*tetragon.KprobeArgument
	var fgsReturnArg *tetragon.KprobeArgument

	process, parent := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
		process.AnnotateProcess(t.enableProcessCred, t.enableProcessNs)
	}

	if parent == nil {
		fgsParent = &tetragon.Process{}
	} else {
		fgsParent = parent.GetProcessCopy()
	}

	for _, arg := range event.Args {
		a := &tetragon.KprobeArgument{}
		switch e := arg.(type) {
		case api.MsgGenericKprobeArgInt:
			a.Arg = &tetragon.KprobeArgument_IntArg{IntArg: e.Value}
		case api.MsgGenericKprobeArgSize:
			a.Arg = &tetragon.KprobeArgument_SizeArg{SizeArg: e.Value}
		case api.MsgGenericKprobeArgString:
			a.Arg = &tetragon.KprobeArgument_StringArg{StringArg: e.Value}
		case api.MsgGenericKprobeArgSock:
			sockArg := &tetragon.KprobeSock{
				Family:   network.InetFamily(e.Family),
				Type:     network.InetType(e.Type),
				Protocol: network.InetProtocol(e.Protocol),
				Mark:     e.Mark,
				Priority: e.Priority,
				Saddr:    e.Saddr,
				Daddr:    e.Daddr,
				Sport:    e.Sport,
				Dport:    e.Dport,
			}
			a.Arg = &tetragon.KprobeArgument_SockArg{SockArg: sockArg}
		case api.MsgGenericKprobeArgSkb:
			skbArg := &tetragon.KprobeSkb{
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
			a.Arg = &tetragon.KprobeArgument_SkbArg{SkbArg: skbArg}
		case api.MsgGenericKprobeArgCred:
			capsArg := &tetragon.KprobeCred{
				Permitted:   caps.GetCapabilitiesTypes(e.Permitted),
				Effective:   caps.GetCapabilitiesTypes(e.Effective),
				Inheritable: caps.GetCapabilitiesTypes(e.Inheritable),
			}
			a.Arg = &tetragon.KprobeArgument_CredArg{CredArg: capsArg}
		case api.MsgGenericKprobeArgBytes:
			if e.OrigSize > uint64(len(e.Value)) {
				a.Arg = &tetragon.KprobeArgument_TruncatedBytesArg{
					TruncatedBytesArg: &tetragon.KprobeTruncatedBytes{
						OrigSize: e.OrigSize,
						BytesArg: e.Value,
					},
				}
			} else {
				a.Arg = &tetragon.KprobeArgument_BytesArg{BytesArg: e.Value}
			}
		case api.MsgGenericKprobeArgFile:
			fileArg := &tetragon.KprobeFile{
				Path:  e.Value,
				Flags: path.FilePathFlagsToStr(e.Flags),
			}
			a.Arg = &tetragon.KprobeArgument_FileArg{FileArg: fileArg}
		case api.MsgGenericKprobeArgPath:
			pathArg := &tetragon.KprobePath{
				Path:  e.Value,
				Flags: path.FilePathFlagsToStr(e.Flags),
			}
			a.Arg = &tetragon.KprobeArgument_PathArg{PathArg: pathArg}
		default:
			logger.GetLogger().WithField("arg", e).Warnf("unexpected type: %T", e)
		}
		if arg.IsReturnArg() {
			fgsReturnArg = a
		} else {
			fgsArgs = append(fgsArgs, a)
		}
	}

	fgsEvent := &tetragon.ProcessKprobe{
		Process:      fgsProcess,
		Parent:       fgsParent,
		FunctionName: event.FuncName,
		Args:         fgsArgs,
		Return:       fgsReturnArg,
		Action:       kprobeAction(event.Action),
	}

	if t.eventCache.Needed(fgsProcess) {
		t.eventCache.Add(process, fgsEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}

	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}
	return fgsEvent
}

func (t *Grpc) HandleGenericKprobeMessage(msg *api.MsgGenericKprobeUnix) *tetragon.GetEventsResponse {
	k := t.GetProcessKprobe(msg)
	if k == nil {
		return nil
	}
	return &tetragon.GetEventsResponse{
		Event:    &tetragon.GetEventsResponse_ProcessKprobe{ProcessKprobe: k},
		NodeName: nodeName,
		Time:     ktime.ToProto(msg.Common.Ktime),
	}
}

type MsgGenericTracepointUnix struct {
	Common     processapi.MsgCommon
	ProcessKey processapi.MsgExecveKey
	Id         int64
	Subsys     string
	Event      string
	Args       []tracingapi.MsgGenericTracepointArg
}

func (t *Grpc) HandleGenericTracepointMessage(msg MsgGenericTracepointUnix) *tetragon.GetEventsResponse {
	var fgsParent, fgsProcess *tetragon.Process

	process, parent := process.GetParentProcessInternal(msg.ProcessKey.Pid, msg.ProcessKey.Ktime)
	if process == nil {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(msg.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = process.UnsafeGetProcess()
	}
	if parent == nil {
		fgsParent = &tetragon.Process{}
	} else {
		fgsParent = parent.GetProcessCopy()
	}

	var fgsArgs []*tetragon.KprobeArgument
	for _, arg := range msg.Args {
		switch v := arg.(type) {
		case uint64:
			fgsArgs = append(fgsArgs, &tetragon.KprobeArgument{Arg: &tetragon.KprobeArgument_SizeArg{
				SizeArg: v,
			}})
		case string:
			fgsArgs = append(fgsArgs, &tetragon.KprobeArgument{Arg: &tetragon.KprobeArgument_StringArg{
				StringArg: v,
			}})

		case []byte:
			fgsArgs = append(fgsArgs, &tetragon.KprobeArgument{Arg: &tetragon.KprobeArgument_BytesArg{
				BytesArg: v,
			}})

		default:
			logger.GetLogger().Warnf("handleGenericTracepointMessage: unhandled value: %+v (%T)", arg, arg)
		}
	}

	fgsEvent := &tetragon.ProcessTracepoint{
		Process: fgsProcess,
		Parent:  fgsParent,
		Subsys:  msg.Subsys,
		Event:   msg.Event,
		Args:    fgsArgs,
	}

	if t.eventCache.Needed(fgsProcess) {
		t.eventCache.Add(process, fgsEvent, ktime.ToProto(msg.Common.Ktime), msg)
		return nil
	}
	if process != nil {
		fgsEvent.Process = process.GetProcessCopy()
	}

	return &tetragon.GetEventsResponse{
		Event:    &tetragon.GetEventsResponse_ProcessTracepoint{ProcessTracepoint: fgsEvent},
		NodeName: nodeName,
		Time:     ktime.ToProto(msg.Common.Ktime),
	}
}

func New(cilium *cilium.State,
	dnsCache *dns.Cache, cache *eventcache.Cache,
	ciliumEnable bool,
	enableProcessCred bool,
	enableProcessNs bool,
) *Grpc {
	return &Grpc{
		ciliumState:  cilium,
		dnsCache:     dnsCache,
		eventCache:   cache,
		enableCilium: ciliumEnable,
	}
}
