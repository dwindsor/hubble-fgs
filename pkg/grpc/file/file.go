//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package file

import (
	"github.com/cilium/hubble/pkg/cilium"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	api "github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/eventcache"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	nodeName = node.GetNodeNameForExport()

	// this should match the enum in bpf/lib/file.h
	fileHookMap = map[uint32]string{
		0: "undef",
		1: "vfs_fallocate",
		2: "rw_verify_area",
		3: "filemap_fault",
		4: "filemap_map_pages",
		5: "filemap_page_mkwrite",
		6: "security_path_unlink",
		7: "do_dentry_open",
	}
)

type Grpc struct {
	dnsCache          *dns.Cache
	ciliumState       *cilium.State
	eventCache        *eventcache.Cache
	enableCilium      bool
	enableProcessCred bool
	enableProcessNs   bool
}

func (t *Grpc) GetProcessFile(event *api.MsgFileEventUnix) *fgs.ProcessFile {
	var tetragonParent, tetragonProcess *tetragon.Process

	process, parent := process.GetParentProcessInternal(event.ProcessKey.Pid, event.ProcessKey.Ktime)
	if process == nil {
		tetragonProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.ProcessKey.Ktime),
		}
	} else {
		tetragonProcess = process.UnsafeGetProcess()
	}
	if parent == nil {
		tetragonParent = &tetragon.Process{}
	} else {
		tetragonParent = parent.GetProcessCopy()
	}

	tetragonEvent := &fgs.ProcessFile{
		Process:     tetragonProcess,
		Parent:      tetragonParent,
		Action:      fgs.FileAction(event.Action),
		Filename:    event.Path,
		InodeNumber: event.Ino,
		Time:        ktime.ToProto(event.Timestamp),
		Hook:        fileHookMap[event.Hook],
	}

	if t.eventCache.Needed(tetragonProcess) {
		t.eventCache.Add(process, tetragonEvent, ktime.ToProto(event.Common.Ktime), event)
		return nil
	}

	if process != nil {
		tetragonEvent.Process = process.GetProcessCopy()
	}
	return tetragonEvent
}

func (t *Grpc) HandleFileMonitoringMessage(msg *api.MsgFileEventUnix) *fgs.GetEventsResponse {
	f := t.GetProcessFile(msg)
	if f == nil {
		return nil
	}
	return &fgs.GetEventsResponse{
		Event:    &fgs.GetEventsResponse_ProcessFile{ProcessFile: f},
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
		ciliumState:       cilium,
		dnsCache:          dnsCache,
		eventCache:        cache,
		enableCilium:      ciliumEnable,
		enableProcessCred: enableProcessCred,
		enableProcessNs:   enableProcessNs,
	}
}
