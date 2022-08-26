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
	"fmt"
	"io/fs"
	"os/user"
	"strconv"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/reader/notify"
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

func GetProcessFile(event *MsgFileEventUnix) *tetragon.ProcessFile {
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

	args := &tetragon.GenericFileArg{
		Filename:    event.Path,
		InodeNumber: event.Ino,
	}
	tetragonEvent := &tetragon.ProcessFile{
		Process: tetragonProcess,
		Parent:  tetragonParent,
		Action:  tetragon.FileAction(event.Action),
		Args:    &tetragon.FileArgument{Arg: &tetragon.FileArgument_GenericArg{GenericArg: args}},
		Time:    ktime.ToProto(event.Timestamp),
		Hook:    fileHookMap[event.Hook],
	}

	if tetragonEvent.Action == tetragon.FileAction_FILE_CREATE {
		userStr := "<unknown>"
		uname, err1 := user.LookupId(strconv.FormatUint(uint64(event.Uid), 10))
		if err1 == nil {
			userStr = uname.Username
		}

		groupStr := "<unknown>"
		gname, err2 := user.LookupGroupId(strconv.FormatUint(uint64(event.Gid), 10))
		if err2 == nil {
			groupStr = gname.Name
		}

		perms := fs.FileMode(event.Imode) & fs.ModePerm
		tetragonEvent.Permissions = fmt.Sprintf("%v (%#o)", perms, perms)
		tetragonEvent.Uid = fmt.Sprintf("%d (%s)", event.Uid, userStr)
		tetragonEvent.Gid = fmt.Sprintf("%d (%s)", event.Gid, groupStr)
	}

	ec := eventcache.Get()
	if ec != nil && ec.Needed(tetragonProcess) {
		ec.Add(process, tetragonEvent, event.ProcessKey.Ktime, event)
		return nil
	}

	if process != nil {
		tetragonEvent.Process = process.GetProcessCopy()
	}
	return tetragonEvent
}

type MsgFileEventUnix struct {
	Common     processapi.MsgCommon
	ProcessKey processapi.MsgExecveKey
	Path       string
	Action     uint32
	Hook       uint32
	Timestamp  uint64
	Ino        uint64
	Imode      uint32
	Uid        uint32
	Gid        uint32
}

func (msg *MsgFileEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	return eventcache.HandleGenericInternal(ev, timestamp)
}

func (msg *MsgFileEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev)
}

func (msg *MsgFileEventUnix) Notify() bool {
	return true
}

func (msg *MsgFileEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	f := GetProcessFile(msg)
	if f == nil {
		return nil
	}
	return &tetragon.GetEventsResponse{
		Event:    &tetragon.GetEventsResponse_ProcessFile{ProcessFile: f},
		NodeName: nodeName,
		Time:     ktime.ToProto(msg.Common.Ktime),
	}
}
