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
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	nodeName = node.GetNodeNameForExport()

	// this should match the enum in bpf/lib/file.h
	fileHookMap = map[uint32]string{
		0:  "undef",
		1:  "vfs_fallocate",
		2:  "rw_verify_area",
		3:  "filemap_fault",
		4:  "filemap_map_pages",
		5:  "filemap_page_mkwrite",
		6:  "security_path_unlink",
		7:  "do_dentry_open",
		8:  "vfs_rmdir",
		9:  "vfs_mkdir",
		10: "vfs_rename",
	}

	renameFlagsString = map[uint32]string{
		0:  "MOVE_INSIDE",
		1:  "MOVE_OUTSIDE",
		2:  "MOVE_INTERNALLY",
		3:  "SRC_REG_FILE",
		4:  "SRC_DIRECTORY",
		5:  "SRC_CHAR_DEV",
		6:  "SRC_BLOCK_DEV",
		7:  "SRC_NAMED_PIPE",
		8:  "SRC_SYMLINK",
		9:  "SRC_SOCKET",
		10: "SRC_INVALID",
		11: "DST_NOT_EXISTS",
		12: "DST_REG_FILE",
		13: "DST_DIRECTORY",
		14: "DST_CHAR_DEV",
		15: "DST_BLOCK_DEV",
		16: "DST_NAMED_PIPE",
		17: "DST_SYMLINK",
		18: "DST_SOCKET",
		19: "DST_INVALID",
	}
)

func getDevMajor(dev uint32) uint32 {
	return dev >> 20
}

func getDevMinor(dev uint32) uint32 {
	one := uint32(1)
	mask := ((one << 20) - 1)
	return dev & mask
}

func createFileSystem(fs MsgFsInfoUnix) *tetragon.FileSystem {
	return &tetragon.FileSystem{
		Dev:  fmt.Sprintf("%d:%d", getDevMajor(fs.SDev), getDevMinor(fs.SDev)),
		Name: fs.SName,
		Id:   fs.SId,
		Uuid: fs.SUuid,
	}
}

func createMntNs(inum uint32) *tetragon.Namespace {
	hostNs := namespace.GetHostNamespace()
	return &tetragon.Namespace{
		Inum:   inum,
		IsHost: hostNs.Mnt.Inum == inum,
	}
}

func createGenericArgs(event *MsgFileEventUnix) *tetragon.FileArgument {
	var ioDetails *tetragon.FileIO

	action := tetragon.FileAction(event.Action)
	ioDetails = nil
	if action == tetragon.FileAction_FILE_WRITE || action == tetragon.FileAction_FILE_READ {
		ioDetails = &tetragon.FileIO{
			Offset: strconv.FormatInt(event.Offset, 10),
			Size:   strconv.FormatUint(uint64(event.Size), 10),
		}
	}
	fileDetails := &tetragon.FileDetails{
		Filename: event.Path,
		Inode: &tetragon.Inode{
			Number: event.Ino,
			Fs:     createFileSystem(event.Fs),
		},
		ParentInode: &tetragon.Inode{
			Number: event.ParentIno,
			Fs:     createFileSystem(event.ParentFs),
		},
	}
	args := &tetragon.GenericFileArg{
		File:  fileDetails,
		Io:    ioDetails,
		MntNs: createMntNs(event.MntNs),
	}
	return &tetragon.FileArgument{Arg: &tetragon.FileArgument_GenericArg{GenericArg: args}}
}

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

	action := tetragon.FileAction(event.Action)
	args := createGenericArgs(event)

	tetragonEvent := &tetragon.ProcessFile{
		Process: tetragonProcess,
		Parent:  tetragonParent,
		Action:  action,
		Args:    args,
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
	if ec != nil &&
		(ec.Needed(tetragonProcess) || (tetragonProcess.Pid.Value > 1 && ec.Needed(tetragonParent))) {
		ec.Add(process, tetragonEvent, event.ProcessKey.Ktime, event)
		return nil
	}

	if process != nil {
		tetragonEvent.Process = process.GetProcessCopy()
	}
	return tetragonEvent
}

type MsgFsInfoUnix struct {
	SDev  uint32
	SName string
	SId   string
	SUuid string
}

type MsgFileEventUnix struct {
	Common     processapi.MsgCommon
	ProcessKey processapi.MsgExecveKey
	Path       string
	Action     uint32
	Hook       uint32
	Timestamp  uint64
	Imode      uint32
	Uid        uint32
	Gid        uint32
	Ino        uint64
	Fs         MsgFsInfoUnix
	ParentIno  uint64
	ParentFs   MsgFsInfoUnix
	Offset     int64
	Size       uint32
	MntNs      uint32
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

func GetRenameFlags(flags uint32) []string {
	var f []string
	for i := uint32(0); i < 32; i++ {
		if (1<<i)&flags != 0 {
			f = append(f, renameFlagsString[i])
		}
	}
	return f
}

func createRenameArgs(event *MsgFileRenameEventUnix) *tetragon.FileArgument {
	src := &tetragon.FileDetails{
		Filename: event.Src.Path,
		Inode: &tetragon.Inode{
			Number: event.Src.Ino,
			Fs:     createFileSystem(event.Src.Fs),
		},
		ParentInode: &tetragon.Inode{
			Number: event.Src.ParentIno,
			Fs:     createFileSystem(event.Src.ParentFs),
		},
	}
	dst := &tetragon.FileDetails{
		Filename: event.Dst.Path,
		Inode: &tetragon.Inode{
			Number: event.Dst.Ino,
			Fs:     createFileSystem(event.Dst.Fs),
		},
		ParentInode: &tetragon.Inode{
			Number: event.Dst.ParentIno,
			Fs:     createFileSystem(event.Dst.ParentFs),
		},
	}
	if dst.Inode.Number == 0 { // the destination name does not exist -- will create new
		dst.Inode.Fs = nil
	}
	args := &tetragon.RenameFileArg{
		Src:   src,
		Dst:   dst,
		MntNs: createMntNs(event.MntNs),
		Flags: GetRenameFlags(event.Flags),
	}
	return &tetragon.FileArgument{Arg: &tetragon.FileArgument_RenameArg{RenameArg: args}}
}

type MsgRenameElemUnix struct {
	Path      string
	Ino       uint64
	Fs        MsgFsInfoUnix
	ParentIno uint64
	ParentFs  MsgFsInfoUnix
}

type MsgFileRenameEventUnix struct {
	Common     processapi.MsgCommon
	ProcessKey processapi.MsgExecveKey
	Action     uint32
	Hook       uint32
	Timestamp  uint64
	Src        MsgRenameElemUnix
	Dst        MsgRenameElemUnix
	MntNs      uint32
	Flags      uint32
}

func GetProcessFileRename(event *MsgFileRenameEventUnix) *tetragon.ProcessFile {
	var tetragonParent, tetragonProcess *tetragon.Process
	var args *tetragon.FileArgument

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

	action := tetragon.FileAction(event.Action)
	args = createRenameArgs(event)
	tetragonEvent := &tetragon.ProcessFile{
		Process: tetragonProcess,
		Parent:  tetragonParent,
		Action:  action,
		Args:    args,
		Time:    ktime.ToProto(event.Timestamp),
		Hook:    fileHookMap[event.Hook],
	}

	ec := eventcache.Get()
	if ec != nil &&
		(ec.Needed(tetragonProcess) ||
			(tetragonProcess.Pid.Value > 1 && ec.Needed(tetragonParent))) {
		ec.Add(process, tetragonEvent, event.ProcessKey.Ktime, event)
		return nil
	}

	if process != nil {
		tetragonEvent.Process = process.GetProcessCopy()
	}
	return tetragonEvent

}

func (msg *MsgFileRenameEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	return eventcache.HandleGenericInternal(ev, timestamp)
}

func (msg *MsgFileRenameEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	return eventcache.HandleGenericEvent(internal, ev)
}

func (msg *MsgFileRenameEventUnix) Notify() bool {
	return true
}

func (msg *MsgFileRenameEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	f := GetProcessFileRename(msg)
	if f == nil {
		return nil
	}
	return &tetragon.GetEventsResponse{
		Event:    &tetragon.GetEventsResponse_ProcessFile{ProcessFile: f},
		NodeName: nodeName,
		Time:     ktime.ToProto(msg.Common.Ktime),
	}
}
