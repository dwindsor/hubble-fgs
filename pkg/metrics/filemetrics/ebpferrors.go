//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package filemetrics

import (
	"path"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	pol "github.com/isovalent/hubble-fgs/pkg/sensors/file/policy"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	fileHookMap = map[int]string{
		fileapi.FileHookUndef:                  "undef",
		fileapi.FileHookVfsFallocate:           "vfs_fallocate",
		fileapi.FileHookSecurityFilePermission: "security_file_permission",
		fileapi.FileHookFilemapFault:           "filemap_fault",
		fileapi.FileHookFilemapMapPages:        "filemap_map_pages",
		fileapi.FileHookFilemapPageMkwrite:     "filemap_page_mkwrite",
		fileapi.FileHookVfsUnlink:              "vfs_unlink",
		fileapi.FileHookSecurityInodeRmdir:     "security_inode_rmdir",
		fileapi.FileHookVfsMkdir:               "vfs_mkdir",
		fileapi.FileHookVfsRename:              "vfs_rename",
		fileapi.FileHookFinishOpen:             "finish_open",
		fileapi.FileHookVfsOpen:                "vfs_open",
		fileapi.FileHookIterateDir:             "iterate_dir",
		fileapi.FileHookDoTruncate:             "do_truncate",
		fileapi.FileHookChmodCommon:            "chmod_common",
		fileapi.FileHookChownCommon:            "chown_common",
		fileapi.FileHookSecurityMmapFile:       "security_mmap_file",
		fileapi.FileHookSecurityInodeUnlink:    "security_inode_unlink",
		fileapi.FileHookSecurityInodeSetattr:   "security_inode_setattr",
		fileapi.FileHookSecurityInodeCreate:    "security_inode_create",
		fileapi.FileHookSecurityInodeMkdir:     "security_inode_mkdir",
		fileapi.FileHookSecurityInodeRename:    "security_inode_rename",
		fileapi.FileHookSecurityBprmCheck:      "security_bprm_check",
		fileapi.FileHookSecurityPathRename:     "security_path_rename",
		fileapi.FileHookIoRead:                 "io_read",
		fileapi.FileHookIoWrite:                "io_write",
		fileapi.FileHookIoIssueSqe:             "io_issue_sqe",
		fileapi.FileHookFsNotify:               "fsnotify",
		fileapi.FileHookSecurityInodeLink:      "security_inode_link",
		fileapi.FileHookSecurityFileOpen:       "security_file_open",
		fileapi.FileHookSecurityKernelReadFile: "security_kernel_read_file",
		fileapi.FileHookSecurityLink:           "security_path_link",
		fileapi.FileHookSecurityMkdir:          "security_path_mkdir",
		fileapi.FileHookSecurityRmdir:          "security_path_rmdir",
		fileapi.FileHookSecurityUnlink:         "security_path_unlink",
	}

	fileErrorReasonMap = map[int]string{
		fileapi.FileErrNoError:                  "success",
		fileapi.FileErrUnknown:                  "unknown",
		fileapi.FileErrGetMsgHeap:               "get_msg_heap",
		fileapi.FileErrDentryFromFile:           "dentry_from_file",
		fileapi.FileErrInodeFromDentry:          "inode_from_dentry",
		fileapi.FileErrParentFromDentry:         "parent_from_dentry",
		fileapi.FileErrFileArg:                  "file_arg",
		fileapi.FileErrInodeFromFile:            "inode_from_file",
		fileapi.FileErrVmaFromVmf:               "vma_from_vmf",
		fileapi.FileErrFileFromVma:              "file_from_vma",
		fileapi.FileErrGetBufferHeap:            "get_buffer_heap",
		fileapi.FileErrGetTrieHeap:              "get_trie_heap",
		fileapi.FileErrGetFileValHeap:           "get_file_val_heap",
		fileapi.FileErrUpdateInodeMap:           "update_inode_map",
		fileapi.FileErrDentryFromPath:           "dentry_from_path",
		fileapi.FileErrDeleteInodeMap:           "delete_inode_map",
		fileapi.FileErrMkdirInfoHeap:            "mkdir_info_heap",
		fileapi.FileErrUpdateMkdirRetprobeMap:   "update_mkdir_retprobe_map",
		fileapi.FileErrDeleteMkdirRetprobeMap:   "delete_mkdir_retprobe_map",
		fileapi.FileErrLookupMkdirRetprobeMap:   "lookup_mkdir_retprobe_map",
		fileapi.FileErrRenameInfoHeap:           "rename_info_heap",
		fileapi.FileErrUpdateRenameRetprobeMap:  "update_rename_retprobe_map",
		fileapi.FileErrDeleteRenameRetprobeMap:  "delete_rename_retprobe_map",
		fileapi.FileErrLookupRenameRetprobeMap:  "lookup_rename_retprobe_map",
		fileapi.FileErrUpdateSprRetprobeMap:     "update_spr_retprobe_map",
		fileapi.FileErrLookupSprRetprobeMap:     "lookup_spr_retprobe_map",
		fileapi.FileErrDeleteSprRetprobeMap:     "delete_spr_retprobe_map",
		fileapi.FileErrUpdateVrRetprobeMap:      "update_vr_retprobe_map",
		fileapi.FileErrLookupVrRetprobeMap:      "lookup_vr_retprobe_map",
		fileapi.FileErrDeleteVrRetprobeMap:      "delete_vr_retprobe_map",
		fileapi.FileErrLookupConfigMap:          "lookup_config_map",
		fileapi.FileErrLookupRenameHeapMap:      "lookup_rename_heap_map",
		fileapi.FileErrFileFromBprm:             "file_from_bprm",
		fileapi.FileErrUpdateExecRetProbeMap:    "update_exec_retprobe_map",
		fileapi.FileErrDeleteExecRetprobeMap:    "delete_exec_retprobe_map",
		fileapi.FileErrUpdateIoUringRetprobeMap: "update_io_uring_retprobe_map",
		fileapi.FileErrDeleteIoUringRetprobeMap: "delete_io_uring_retprobe_map",
		fileapi.FileErrLookupIoUringRetprobeMap: "lookup_io_uring_retprobe_map",
		fileapi.FileErrUpdateIoUringMap:         "update_io_uring_map",
		fileapi.FileErrDeleteIoUringMap:         "delete_io_uring_map",
		fileapi.FileErrIoUringTask:              "get_io_uring_task",
		fileapi.FileErrUpdateFsNotifyMap:        "update_fsnotify_map",
		fileapi.FileErrDeleteFsNotifyMap:        "delete_fsnotify_map",
		fileapi.FileErrLookupPatternsMap:        "lookup_patterns_map",
		fileapi.FileErrUnexpected:               "unexpected",
	}
)

// bpfCollector implements prometheus.Collector. It collects metrics directly from BPF maps.
type bpfErrorCollector struct{}

func NewBPFErrorCollector() prometheus.Collector {
	return &bpfErrorCollector{}
}

func (c *bpfErrorCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- fileKernelErrors.Desc()
}

func (c *bpfErrorCollector) Collect(ch chan<- prometheus.Metric) {
	for _, tp := range pol.FileMonitoringTable.GetValuesFIM() {
		filePinPath := path.Join(option.Config.BpfDir, sensors.PathJoin(tp.PinPath, "file_errors_map"))
		fileMapHandle, err := ebpf.LoadPinnedMap(filePinPath, nil)
		if err != nil {
			return
		}
		defer fileMapHandle.Close()

		var zero uint32
		var allCpuValue []fileapi.FileErrors
		if err := fileMapHandle.Lookup(zero, &allCpuValue); err != nil {
			continue
		}

		var sum fileapi.FileErrors
		for _, val := range allCpuValue {
			for i := 0; i < fileapi.FileHookMax; i++ {
				for j := 0; j < fileapi.FileErrMax; j++ {
					sum.M[i][j] += val.M[i][j]
				}
			}
		}

		for i := 0; i < fileapi.FileHookMax; i++ {
			for j := 0; j < fileapi.FileErrMax; j++ {
				if sum.M[i][j] != 0 {
					hook, ok := fileHookMap[i]
					if !ok {
						hook = "undef"
					}

					reason, ok := fileErrorReasonMap[j]
					if !ok {
						reason = "undef"
					}

					ch <- fileKernelErrors.MustMetric(float64(sum.M[i][j]), tp.PolicyName, hook, reason)
				}
			}
		}
	}
}
