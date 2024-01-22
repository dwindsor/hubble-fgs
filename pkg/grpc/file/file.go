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
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/eventcache"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	"github.com/isovalent/hubble-fgs/pkg/metrics/filemetrics"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	origId = 0
	newId  = 1
)

var (
	nodeName = node.GetNodeNameForExport()

	// this should match the enum in bpf/lib/file.h
	fileHookMap = map[uint32]string{
		0:  "undef",
		1:  "vfs_fallocate",
		2:  "security_file_permission",
		3:  "filemap_fault",
		4:  "filemap_map_pages",
		5:  "filemap_page_mkwrite",
		6:  "vfs_unlink",
		7:  "security_inode_rmdir",
		8:  "vfs_mkdir",
		9:  "vfs_rename",
		10: "finish_open",
		11: "vfs_open",
		12: "iterate_dir",
		13: "do_truncate",
		14: "chmod_common",
		15: "chown_common",
		16: "hook_security_mmap_file",
		17: "hook_security_inode_unlink",
		18: "hook_security_inode_setattr",
		19: "hook_security_inode_create",
		20: "hook_security_inode_mkdir",
		21: "hook_security_inode_rename",
		22: "hook_security_bprm_check",
		23: "hook_security_path_rename",
		24: "hook_io_read",
		25: "hook_io_write",
		26: "hook_io_issue_sqe",
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

func createFileSystem(fs MsgFsInfoUnix, sDev uint32) *tetragon.FileSystem {
	// In the case where we block a create/mkdir operation we don't have
	// file system information. So there is no need to print zero field.
	if sDev == 0 {
		return nil
	}
	return &tetragon.FileSystem{
		Dev:  fmt.Sprintf("%d:%d", getDevMajor(sDev), getDevMinor(sDev)),
		Name: fs.SName,
		Id:   fs.SId,
		Uuid: fs.SUuid,
	}
}

func createMntNs(inum uint32) *tetragon.Namespace {
	hostNs, _ := namespace.InitHostNamespace()
	return &tetragon.Namespace{
		Inum:   inum,
		IsHost: hostNs.Mnt.Inum == inum,
	}
}

func createGenericArgs(event *MsgFileEventUnix) *tetragon.FileArgument {

	fileDetails := &tetragon.FileDetails{
		Filename: &tetragon.FileDetails_Str{Str: event.Path},
		Inode: &tetragon.Inode{
			Number: event.Msg.Ino,
			Fs:     createFileSystem(event.Fs, event.Msg.Fs.SDev),
		},
		ParentInode: &tetragon.Inode{
			Number: event.Msg.ParentIno,
			Fs:     createFileSystem(event.ParentFs, event.Msg.ParentFs.SDev),
		},
		Location: &tetragon.FileLocation{},
	}
	args := &tetragon.GenericFileArg{
		File:  fileDetails,
		MntNs: createMntNs(event.Msg.MntNs),
	}
	if event.Msg.Digest.Ok != 0 {
		args.Digest = &tetragon.FileDigest{
			Hash:  event.Digest.Hash,
			Algo:  tetragon.DigestAlgo(event.Msg.Digest.Algo),
			Error: int64(event.Digest.Error),
		}
	}
	return &tetragon.FileArgument{Arg: &tetragon.FileArgument_GenericArg{GenericArg: args}}
}

func createReadDirArgs(event *MsgFileEventUnix) *tetragon.FileArgument {
	fileDetails := &tetragon.FileDetails{
		Filename: &tetragon.FileDetails_Str{Str: event.Path},
		Inode: &tetragon.Inode{
			Number: event.Msg.Ino,
			Fs:     createFileSystem(event.Fs, event.Msg.Fs.SDev),
		},
		ParentInode: &tetragon.Inode{
			Number: event.Msg.ParentIno,
			Fs:     createFileSystem(event.ParentFs, event.Msg.ParentFs.SDev),
		},
		Location: &tetragon.FileLocation{},
	}
	args := &tetragon.ReadDirArg{
		File:  fileDetails,
		MntNs: createMntNs(event.Msg.MntNs),
	}
	return &tetragon.FileArgument{Arg: &tetragon.FileArgument_ReaddirArg{ReaddirArg: args}}

}

func createAttrArgs(event *MsgFileEventUnix) *tetragon.FileArgument {
	fileDetails := &tetragon.FileDetails{
		Filename: &tetragon.FileDetails_Str{Str: event.Path},
		Inode: &tetragon.Inode{
			Number: event.Msg.Ino,
			Fs:     createFileSystem(event.Fs, event.Msg.Fs.SDev),
		},
		ParentInode: &tetragon.Inode{
			Number: event.Msg.ParentIno,
			Fs:     createFileSystem(event.ParentFs, event.Msg.ParentFs.SDev),
		},
		Location: &tetragon.FileLocation{},
	}

	var perm *tetragon.AttrChange
	if event.Msg.Imode[origId] != 0xFFFF { // UINT16_MAX
		n := fs.FileMode(event.Msg.Imode[newId]) & fs.ModePerm
		o := fs.FileMode(event.Msg.Imode[origId]) & fs.ModePerm
		perm = &tetragon.AttrChange{
			New: fmt.Sprintf("%v (%#o)", n, n),
			Old: fmt.Sprintf("%v (%#o)", o, o),
		}
	}

	var uid *tetragon.AttrChange
	if event.Msg.Uid[origId] != 0xFFFFFFFF { // UINT32_MAX
		uid = &tetragon.AttrChange{
			New: fmt.Sprintf("%d", event.Msg.Uid[newId]),
			Old: fmt.Sprintf("%d", event.Msg.Uid[origId]),
		}
	}

	var gid *tetragon.AttrChange
	if event.Msg.Gid[origId] != 0xFFFFFFFF { // UINT32_MAX
		gid = &tetragon.AttrChange{
			New: fmt.Sprintf("%d", event.Msg.Gid[newId]),
			Old: fmt.Sprintf("%d", event.Msg.Gid[origId]),
		}
	}

	attrs := &tetragon.FileAttr{
		Permissions: perm,
		Uid:         uid,
		Gid:         gid,
	}

	args := &tetragon.AttrArg{
		File:  fileDetails,
		Attr:  attrs,
		MntNs: createMntNs(event.Msg.MntNs),
	}

	return &tetragon.FileArgument{Arg: &tetragon.FileArgument_AttrArg{AttrArg: args}}
}

func populateFileLocation(event *MsgFileEventUnix, tetragonProcess *tetragon.Process, fileLocation *tetragon.FileLocation) {
	if event.ContainerID == "" {
		fileLocation.Type = tetragon.FileScope_HOST_FILE
	} else {
		// We may truncate tetragonProcess.Docker in some places to fix
		// some kernel buffers. event.ContainerID is user provided and
		// can be the full container ID length. Thus we use HasPrefix
		// to cover where they have different length.
		if strings.HasPrefix(event.ContainerID, tetragonProcess.Docker) {
			fileLocation.Type = tetragon.FileScope_CONTAINER_FILE_LOCAL
		} else {
			fileLocation.Type = tetragon.FileScope_CONTAINER_FILE_REMOTE
			if option.Config.EnableK8s {
				podInfo := process.GetPodInfo(event.ContainerID, "", "", 0)
				fileLocation.Pod = podInfo
			}
		}
		fileLocation.ContainerId = event.ContainerID
	}
}

func normalizeOp(op uint32) tetragon.FileOperation {
	if op&uint32(tetragon.FileOperation_FILE_OP_BLOCK) != 0 {
		return tetragon.FileOperation_FILE_OP_BLOCK
	} else if op&uint32(tetragon.FileOperation_FILE_OP_POST) != 0 {
		return tetragon.FileOperation_FILE_OP_POST
	}
	return tetragon.FileOperation_FILE_OP_UNKNOWN
}

func handleFileTotalActionEvents(tetragonEvent *tetragon.ProcessFile, tpName, tpRule string) {
	if tetragonEvent == nil || tetragonEvent.Process == nil { // we don't expect these
		filemetrics.FileTotalErrorsInc("grpc_nil_ev_proc")
		return
	}

	act, ok := tetragon.FileAction_name[int32(tetragonEvent.Action)]
	if !ok {
		filemetrics.FileTotalErrorsInc("grpc_not_valid_action")
		return
	}

	if len(tetragonEvent.Operation) != 1 { // for now we will always have a single operation
		filemetrics.FileTotalErrorsInc("grpc_op_gt_one")
		return
	}

	opr, ok := tetragon.FileOperation_name[int32(tetragonEvent.Operation[0])]
	if !ok {
		filemetrics.FileTotalErrorsInc("grpc_not_valid_op")
		return
	}

	namespace := "<host>" // this refers to host, < and > are not valid characters for namespace names and thus we can distinguish a namespace named "host"
	workload := "<host>"  // this refers to host, < and > are not valid characters for namespace names and thus we can distinguish a namespace named "host"
	pod := "<host>"       // this refers to host, < and > are not valid characters for namespace names and thus we can distinguish a namespace named "host"
	if tetragonEvent.Process.Pod != nil {
		namespace = tetragonEvent.Process.Pod.Namespace
		workload = tetragonEvent.Process.Pod.Workload
		pod = tetragonEvent.Process.Pod.Name
	}

	filemetrics.FileTotalActionEventsInc(
		nodeName,
		namespace,
		workload,
		pod,
		tpName,
		tpRule,
		act,
		opr,
	)
}

func handleFileExecTotalActionEvents(tetragonEvent *tetragon.ProcessFileExec, execFile, execDigest string) {
	if tetragonEvent == nil || tetragonEvent.Process == nil { // we don't expect these
		return
	}

	if len(tetragonEvent.Operations) != 1 { // for now we will always have a single operation
		return
	}

	opr, ok := tetragon.FileOperation_name[int32(tetragonEvent.Operations[0])]
	if !ok {
		return
	}

	namespace := "<host>" // this refers to host, < and > are not valid characters for namespace names and thus we can distinguish a namespace named "host"
	workload := "<host>"  // this refers to host, < and > are not valid characters for namespace names and thus we can distinguish a namespace named "host"
	pod := "<host>"       // this refers to host, < and > are not valid characters for namespace names and thus we can distinguish a namespace named "host"
	if tetragonEvent.Process.Pod != nil {
		namespace = tetragonEvent.Process.Pod.Namespace
		workload = tetragonEvent.Process.Pod.Workload
		pod = tetragonEvent.Process.Pod.Name
	}

	filemetrics.FileExecTotalActionEventsInc(
		nodeName,
		namespace,
		workload,
		pod,
		execFile,
		execDigest,
		opr,
	)
}

func GetProcessFile(event *MsgFileEventUnix) *tetragon.ProcessFile {
	var tetragonParent, tetragonProcess *tetragon.Process

	internal, parent := process.GetParentProcessInternal(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if internal == nil {
		tetragonProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
		}
	} else {
		tetragonProcess = internal.UnsafeGetProcess()
	}
	if parent != nil {
		tetragonParent = parent.UnsafeGetProcess()
	}

	action := tetragon.FileAction(event.Msg.Action)
	var args *tetragon.FileArgument
	if action == tetragon.FileAction_FILE_READDIR {
		args = createReadDirArgs(event)
		fileLocation := args.GetReaddirArg().GetFile().GetLocation()
		populateFileLocation(event, tetragonProcess, fileLocation)
	} else if action == tetragon.FileAction_FILE_CHATTR {
		args = createAttrArgs(event)
		fileLocation := args.GetAttrArg().GetFile().GetLocation()
		populateFileLocation(event, tetragonProcess, fileLocation)
	} else {
		args = createGenericArgs(event)
		fileLocation := args.GetGenericArg().GetFile().GetLocation()
		populateFileLocation(event, tetragonProcess, fileLocation)
	}

	tetragonEvent := &tetragon.ProcessFile{
		Process:   tetragonProcess,
		Parent:    tetragonParent,
		Action:    action,
		Args:      args,
		Time:      ktime.ToProto(event.Msg.Timestamp),
		Hook:      fileHookMap[event.Msg.Hook],
		Operation: []tetragon.FileOperation{normalizeOp(event.Msg.Operation)},
	}

	if tetragonEvent.Action == tetragon.FileAction_FILE_CREATE {
		userStr := "<unknown>"
		uname, err1 := user.LookupId(strconv.FormatUint(uint64(event.Msg.Uid[origId]), 10))
		if err1 == nil {
			userStr = uname.Username
		}

		groupStr := "<unknown>"
		gname, err2 := user.LookupGroupId(strconv.FormatUint(uint64(event.Msg.Gid[origId]), 10))
		if err2 == nil {
			groupStr = gname.Name
		}

		perms := fs.FileMode(event.Msg.Imode[origId]) & fs.ModePerm
		tetragonEvent.Permissions = fmt.Sprintf("%v (%#o)", perms, perms)
		tetragonEvent.Uid = fmt.Sprintf("%d (%s)", event.Msg.Uid[origId], userStr)
		tetragonEvent.Gid = fmt.Sprintf("%d (%s)", event.Msg.Gid[origId], groupStr)
	}

	filemetrics.FileTotalEventsInc()

	ec := eventcache.Get()
	if ec != nil &&
		(ec.Needed(tetragonProcess) || (tetragonProcess.Pid.Value > 1 && ec.Needed(tetragonParent))) {
		filemetrics.FileTotalCacheInEventsInc()
		ec.Add(nil, tetragonEvent, event.Msg.Common.Ktime, event.Msg.ProcessKey.Ktime, event)
		return nil
	}

	if internal != nil {
		tetragonEvent.Process = internal.GetProcessCopy()
		process.UpdateEventProcessTid(tetragonEvent.Process, &event.Msg.Tid)
	}
	handleFileTotalActionEvents(tetragonEvent, event.TpName, event.TpRule)
	return tetragonEvent
}

func GetProcessFileExec(event *MsgFileEventUnix) *tetragon.ProcessFileExec {
	var tetragonParent, tetragonProcess *tetragon.Process

	internal, parent := process.GetParentProcessInternal(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if internal == nil {
		tetragonProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
		}
	} else {
		tetragonProcess = internal.UnsafeGetProcess()
	}
	if parent != nil {
		tetragonParent = parent.UnsafeGetProcess()
	}

	tetragonEvent := &tetragon.ProcessFileExec{
		Process:    tetragonProcess,
		Parent:     tetragonParent,
		Operations: []tetragon.FileOperation{normalizeOp(event.Msg.Operation)},
	}

	tetragonEvent.File = &tetragon.FileDetails{
		Filename: &tetragon.FileDetails_Str{Str: event.Path},
		Inode: &tetragon.Inode{
			Number: event.Msg.Ino,
			Fs:     createFileSystem(event.Fs, event.Msg.Fs.SDev),
		},
		ParentInode: &tetragon.Inode{
			Number: event.Msg.ParentIno,
			Fs:     createFileSystem(event.ParentFs, event.Msg.ParentFs.SDev),
		},
	}

	if event.Msg.Digest.Ok != 0 {
		tetragonEvent.Digest = &tetragon.FileDigest{
			Hash:  event.Digest.Hash,
			Algo:  tetragon.DigestAlgo(event.Msg.Digest.Algo),
			Error: int64(event.Digest.Error),
		}
	}

	filemetrics.FileExecTotalEventsInc()

	ec := eventcache.Get()
	if ec != nil && (ec.Needed(tetragonProcess) || (tetragonProcess.Pid.Value > 1 && ec.Needed(tetragonParent))) {
		filemetrics.FileExecTotalCacheInEventsInc()
		ec.Add(nil, tetragonEvent, event.Msg.Common.Ktime, event.Msg.ProcessKey.Ktime, event)
		return nil
	}

	if internal != nil {
		tetragonEvent.Process = internal.GetProcessCopy()
		process.UpdateEventProcessTid(tetragonEvent.Process, &event.Msg.Tid)
	}
	handleFileExecTotalActionEvents(
		tetragonEvent,
		tetragonEvent.File.GetStr(),
		fmt.Sprintf("%s:%s", tetragon.DigestAlgo_name[event.Msg.Digest.Algo], tetragonEvent.Digest.Hash),
	)
	return tetragonEvent
}

type MsgFsInfoUnix struct {
	SName string
	SId   string
	SUuid string
}

type MsgDigest struct {
	Hash  string
	Error int32
}

type MsgFileEventUnix struct {
	Msg         *fileapi.MsgFileEvent
	Path        string
	Fs          MsgFsInfoUnix
	ParentFs    MsgFsInfoUnix
	ContainerID string
	TpName      string
	TpRule      string
	Digest      MsgDigest
}

func handleFileEventCacheRetryMetrics(ev notify.Event, msg *MsgFileEventUnix) {
	event := ev.Encapsulate()
	switch e := event.(type) {
	case *tetragon.GetEventsResponse_ProcessFile:
		handleFileTotalActionEvents(e.ProcessFile, msg.TpName, msg.TpRule)
	case *tetragon.GetEventsResponse_ProcessFileExec:
		handleFileExecTotalActionEvents(e.ProcessFileExec, msg.Path, fmt.Sprintf("%s:%s", tetragon.DigestAlgo_name[msg.Msg.Digest.Algo], msg.Digest.Hash))
	default:
		filemetrics.FileTotalErrorsInc("grpc_eventcache_retry")
	}
}

func (msg *MsgFileEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	p := ev.GetProcess()
	return eventcache.HandleGenericInternal(ev, p.Pid.Value, &msg.Msg.Tid, timestamp)
}

func (msg *MsgFileEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	if err := eventcache.HandleGenericEvent(internal, ev, nil); err != nil {
		return err
	}
	handleFileEventCacheRetryMetrics(ev, msg)
	return nil
}

func (msg *MsgFileEventUnix) Notify() bool {
	if !msg.isFileExecEvent() {
		filemetrics.FileTotalCacheOutEventsInc()
	} else {
		filemetrics.FileExecTotalCacheOutEventsInc()
	}
	return true
}

func (msg *MsgFileEventUnix) isFileExecEvent() bool {
	return msg.Msg.Action == 0xFFFFFFFF && msg.Msg.Hook == 0xFFFFFFFF
}

func (msg *MsgFileEventUnix) HandleMessage() *tetragon.GetEventsResponse {
	if msg.isFileExecEvent() {
		f := GetProcessFileExec(msg)
		if f == nil {
			return nil
		}
		return &tetragon.GetEventsResponse{
			Event:    &tetragon.GetEventsResponse_ProcessFileExec{ProcessFileExec: f},
			NodeName: nodeName,
			Time:     ktime.ToProto(msg.Msg.Common.Ktime),
		}
	}
	f := GetProcessFile(msg)
	if f == nil {
		return nil
	}
	return &tetragon.GetEventsResponse{
		Event:    &tetragon.GetEventsResponse_ProcessFile{ProcessFile: f},
		NodeName: nodeName,
		Time:     ktime.ToProto(msg.Msg.Common.Ktime),
	}
}

func (msg *MsgFileEventUnix) Cast(_ interface{}) notify.Message {
	return &MsgFileEventUnix{}
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
		Filename: &tetragon.FileDetails_Str{Str: event.Src.Path},
		Inode: &tetragon.Inode{
			Number: event.Msg.Src.Ino,
			Fs:     createFileSystem(event.Src.Fs, event.Msg.Src.Fs.SDev),
		},
		ParentInode: &tetragon.Inode{
			Number: event.Msg.Src.ParentIno,
			Fs:     createFileSystem(event.Src.ParentFs, event.Msg.Src.ParentFs.SDev),
		},
		Location: &tetragon.FileLocation{},
	}
	dst := &tetragon.FileDetails{
		Filename: &tetragon.FileDetails_Str{Str: event.Dst.Path},
		Inode: &tetragon.Inode{
			Number: event.Msg.Dst.Ino,
			Fs:     createFileSystem(event.Dst.Fs, event.Msg.Dst.Fs.SDev),
		},
		ParentInode: &tetragon.Inode{
			Number: event.Msg.Dst.ParentIno,
			Fs:     createFileSystem(event.Dst.ParentFs, event.Msg.Dst.ParentFs.SDev),
		},
		Location: &tetragon.FileLocation{},
	}
	if dst.Inode.Number == 0 { // the destination name does not exist -- will create new
		dst.Inode.Fs = nil
	}
	args := &tetragon.RenameFileArg{
		Src:   src,
		Dst:   dst,
		MntNs: createMntNs(event.Msg.MntNs),
		Flags: GetRenameFlags(event.Msg.Flags),
	}
	return &tetragon.FileArgument{Arg: &tetragon.FileArgument_RenameArg{RenameArg: args}}
}

type MsgRenameElemUnix struct {
	Path        string
	Fs          MsgFsInfoUnix
	ParentFs    MsgFsInfoUnix
	ContainerID string
}

type MsgFileRenameEventUnix struct {
	Msg    *fileapi.MsgFileRenameEvent
	Src    MsgRenameElemUnix
	Dst    MsgRenameElemUnix
	TpName string
	TpRule string
}

func GetProcessFileRename(event *MsgFileRenameEventUnix) *tetragon.ProcessFile {
	var tetragonParent, tetragonProcess *tetragon.Process
	var args *tetragon.FileArgument

	internal, parent := process.GetParentProcessInternal(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if internal == nil {
		tetragonProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
		}
	} else {
		tetragonProcess = internal.UnsafeGetProcess()
	}
	if parent != nil {
		tetragonParent = parent.UnsafeGetProcess()
	}

	action := tetragon.FileAction(event.Msg.Action)
	args = createRenameArgs(event)

	// setup src file location
	srcFileLocation := args.GetRenameArg().GetSrc().GetLocation()
	if event.Src.ContainerID == "" {
		srcFileLocation.Type = tetragon.FileScope_HOST_FILE
	} else {
		// We may truncate tetragonProcess.Docker in some places to fix
		// some kernel buffers. event.ContainerID is user provided and
		// can be the full container ID length. Thus we use HasPrefix
		// to cover where they have different length.
		if strings.HasPrefix(event.Src.ContainerID, tetragonProcess.Docker) {
			srcFileLocation.Type = tetragon.FileScope_CONTAINER_FILE_LOCAL
		} else {
			srcFileLocation.Type = tetragon.FileScope_CONTAINER_FILE_REMOTE
			if option.Config.EnableK8s {
				podInfo := process.GetPodInfo(event.Src.ContainerID, "", "", 0)
				srcFileLocation.Pod = podInfo
			}
		}
		srcFileLocation.ContainerId = event.Src.ContainerID
	}

	// setup dst file location
	dstFileLocation := args.GetRenameArg().GetDst().GetLocation()
	if event.Dst.ContainerID == "" {
		dstFileLocation.Type = tetragon.FileScope_HOST_FILE
	} else {
		// We may truncate tetragonProcess.Docker in some places to fix
		// some kernel buffers. event.ContainerID is user provided and
		// can be the full container ID length. Thus we use HasPrefix
		// to cover where they have different length.
		if strings.HasPrefix(event.Dst.ContainerID, tetragonProcess.Docker) {
			dstFileLocation.Type = tetragon.FileScope_CONTAINER_FILE_LOCAL
		} else {
			dstFileLocation.Type = tetragon.FileScope_CONTAINER_FILE_REMOTE
			if option.Config.EnableK8s {
				podInfo := process.GetPodInfo(event.Dst.ContainerID, "", "", 0)
				dstFileLocation.Pod = podInfo
			}
		}
		dstFileLocation.ContainerId = event.Dst.ContainerID
	}

	tetragonEvent := &tetragon.ProcessFile{
		Process:   tetragonProcess,
		Parent:    tetragonParent,
		Action:    action,
		Args:      args,
		Time:      ktime.ToProto(event.Msg.Timestamp),
		Hook:      fileHookMap[event.Msg.Hook],
		Operation: []tetragon.FileOperation{normalizeOp(event.Msg.Operation)},
	}

	filemetrics.FileTotalEventsInc()

	ec := eventcache.Get()
	if ec != nil &&
		(ec.Needed(tetragonProcess) ||
			(tetragonProcess.Pid.Value > 1 && ec.Needed(tetragonParent))) {
		filemetrics.FileTotalCacheInEventsInc()
		ec.Add(nil, tetragonEvent, event.Msg.Common.Ktime, event.Msg.ProcessKey.Ktime, event)
		return nil
	}

	if internal != nil {
		tetragonEvent.Process = internal.GetProcessCopy()
		process.UpdateEventProcessTid(tetragonEvent.Process, &event.Msg.Tid)
	}
	handleFileTotalActionEvents(tetragonEvent, event.TpName, event.TpRule)
	return tetragonEvent

}

func (msg *MsgFileRenameEventUnix) RetryInternal(ev notify.Event, timestamp uint64) (*process.ProcessInternal, error) {
	p := ev.GetProcess()
	return eventcache.HandleGenericInternal(ev, p.Pid.Value, &msg.Msg.Tid, timestamp)
}

func (msg *MsgFileRenameEventUnix) Retry(internal *process.ProcessInternal, ev notify.Event) error {
	if err := eventcache.HandleGenericEvent(internal, ev, nil); err != nil {
		return err
	}
	handleFileEventCacheRetryMetrics(ev, &MsgFileEventUnix{TpName: msg.TpName, TpRule: msg.TpRule})
	return nil
}

func (msg *MsgFileRenameEventUnix) Notify() bool {
	filemetrics.FileTotalCacheOutEventsInc()
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
		Time:     ktime.ToProto(msg.Msg.Common.Ktime),
	}
}

func (msg *MsgFileRenameEventUnix) Cast(_ interface{}) notify.Message {
	return &MsgFileRenameEventUnix{}
}
