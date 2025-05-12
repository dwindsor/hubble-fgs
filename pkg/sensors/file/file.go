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
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	mapHelpers "maps"
	"net/rpc"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/bpf"
	ossBTF "github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/cgtracker"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/podhooks"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/cilium/tetragon/pkg/strutils"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"

	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	fgsBTF "github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/grpc/file"
	"github.com/isovalent/hubble-fgs/pkg/metrics/filemetrics"
	eeOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	pol "github.com/isovalent/hubble-fgs/pkg/sensors/file/policy"
	fm "github.com/isovalent/hubble-fgs/pkg/sensors/file/utils"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"

	"github.com/google/uuid"
)

type Mode uint32

const (
	Observe Mode = iota
	EnforceNotSupported
	EnforceFmodRet
	EnforceLSM
	PathBasedNotSupported
	PathBased // this is used both for observability and enforcement
)

type TpMode uint32

const (
	InodeBasedTpMode = 0x01
	PathBasedTpMode  = 0x02
	MixedTpMode      = InodeBasedTpMode | PathBasedTpMode // This requires both inode and path based hooks. For now this is not supported.
)

type PathBasedMatcher uint32

const (
	InvalidMatcher PathBasedMatcher = iota
	MatchAll
	FsTypeMatcher
)

var fsScannerCmd *exec.Cmd
var fsScannerCancelFn context.CancelFunc
var fsScannerCancelFnMtx sync.Mutex

var policyIdToTailId = map[uint32]uint32{}

const maxTailId = uint32(1024)

type MapType uint32

const (
	UnknownMap MapType = iota
	SkipMap
	PrivateMap
	SharedMap
	BaseMap
)

type MapInfo struct {
	name string
	tp   MapType
}

type FimFunc struct {
	proto, progName, progSection string
	maps                         [][]MapInfo
}

type FimHook struct {
	tp, name string
	prog     []FimFunc
}

type FimProg struct {
	tp, name, progName, progSection string
	maps                            []MapInfo
}

var (
	PathBasedSelectorMaps = []MapInfo{
		{"selectors_ctx_heap", PrivateMap},       // for selectors with __V61_BPF_PROG
		{"file_prefix_lpm_heap", PrivateMap},     // for matchBinaries
		{"file_msg_caps_heap", PrivateMap},       // for matchLinuxCapabilities
		{"file_msg_ns_heap", PrivateMap},         // for matchLinuxNamespaces
		{"digest_heap_map", PrivateMap},          // for matchFilename InFileWithDigest operator
		{"filename_heap_map", PrivateMap},        // for matchFilename InFileWithDigest operator
		{"file_ops_maps", SharedMap},             // for matchOperations
		{"file_uidgid_map", SharedMap},           // for matchUidGid
		{"file_proc_dur_map", SharedMap},         // for matchProcessDuration
		{"file_actions_map", SharedMap},          // for matchActions
		{"file_capabilities_map", SharedMap},     // for matchLinuxCapabilities
		{"file_namespaces_map", SharedMap},       // for matchLinuxNamespaces
		{"file_open_flags_map", SharedMap},       // for matchOpenFlags
		{"file_rename_map", SharedMap},           // for matchRenameSrcType
		{"filename_ops_map", SharedMap},          // for matchFilename operator
		{"filename_digest_map", SharedMap},       // for matchFilename InFileWithDigest operator
		{"filename_path_map", SharedMap},         // for matchFilename InFileWithDigest operator
		{"glob_patterns_map", SharedMap},         // for matchFilename InPattern operator
		{"glob_temp_maps", SharedMap},            // for matchFilename InPattern operator
		{"tg_mb_sel_opts", SharedMap},            // for matchBinaries operator
		{"tg_mb_paths", SharedMap},               // for matchBinaries In/NotIn operator
		{"string_prefix_maps", SharedMap},        // for matchBinaries Prefix/NoPrefix operator
		{"string_postfix_maps", SharedMap},       // for matchBinaries Postfix/NoPostfix operator
		{"string_postfix_maps_heap", PrivateMap}, // for matchBinaries Postfix/NoPostfix operator
		{"exec_attributes_map", SharedMap},
	}

	InodeBasedSelectorMaps = []MapInfo{
		{"file_msg_caps_heap", PrivateMap},       // for matchLinuxCapabilities
		{"file_msg_ns_heap", PrivateMap},         // for matchLinuxNamespaces
		{"file_prefix_lpm_heap", PrivateMap},     // for matchBinaries
		{"file_actions_map", SharedMap},          // for matchActions
		{"file_capabilities_map", SharedMap},     // for matchLinuxCapabilities
		{"file_namespaces_map", SharedMap},       // for matchLinuxNamespaces
		{"file_ops_maps", SharedMap},             // for matchOperations
		{"file_uidgid_map", SharedMap},           // for matchUidGid
		{"file_proc_dur_map", SharedMap},         // for matchProcessDuration
		{"string_prefix_maps", SharedMap},        // for matchBinaries Prefix/NoPrefix operator
		{"string_postfix_maps", SharedMap},       // for matchBinaries Postfix/NoPostfix operator
		{"string_postfix_maps_heap", PrivateMap}, // for matchBinaries Postfix/NoPostfix operator
		{"tg_mb_sel_opts", SharedMap},            // for matchBinaries operator
		{"tg_mb_paths", SharedMap},               // for matchBinaries In/NotIn operator
	}

	PathBasedMiscMaps = []MapInfo{
		{"buffer_heap_map", PrivateMap},     // for d_path_local
		{"file_config_map", SharedMap},      // for configuration options
		{"file_errors_map", SharedMap},      // for eBPF errors
		{"file_system_type_map", SharedMap}, // for FileSystemType type in file_paths_patterns
	}

	InodeBasedMiscMaps = []MapInfo{
		{"file_config_map", SharedMap},      // for configuration options
		{"file_errors_map", SharedMap},      // for eBPF errors
		{"hash_map_inode_alloc", SharedMap}, // for all inodes
	}

	InodeStatsMap = []MapInfo{
		{"hash_map_inode_alloc_stats", SharedMap},
	}

	BaseMaps = []MapInfo{
		{"tcpmon_map", BaseMap},
		{"execve_map", BaseMap},
		{"policy_filter_maps", BaseMap},
		{"tg_conf_map", BaseMap},
		{"tg_cgtracker_map", BaseMap},
		{"tg_stats_map", BaseMap},
	}

	SkipMaps = []MapInfo{
		{".rodata", SkipMap}, // possibly due to PATH_BASED_MATCHER and USE_BPF_D_PATH_HELPER
	}

	IoUringMaps = []MapInfo{
		{"io_uring_map", SharedMap}, // for io_uring process information
		{"io_uring_retprobe_map", SharedMap},
		{"file_errors_map", SharedMap}, // for eBPF errors
	}

	KprobeMkdirMaps = []MapInfo{
		{"file_heap_map", PrivateMap}, // for struct msg_file_ops
		{"lpm_trie_heap_key", PrivateMap},
		{"lpm_trie_map_alloc", SharedMap},
		{"execve_map", BaseMap},
		{"policy_filter_maps", BaseMap},
		{"buffer_heap_map", PrivateMap}, // for d_path_local
		{"tg_conf_map", BaseMap},
		{"tg_cgtracker_map", BaseMap},
		{"vfs_mkdir_info_heap", PrivateMap},
		{"mkdir_retprobe_map", SharedMap},
	}

	KretprobeMkdirMaps = []MapInfo{
		{"tcpmon_map", BaseMap},
		{"tg_stats_map", BaseMap},
		{"mkdir_retprobe_map", SharedMap},
		{"file_errors_map", SharedMap}, // for eBPF errors
		{"file_heap_map", PrivateMap},  // for struct msg_file_ops
		{"file_val_map", PrivateMap},
		{"hash_map_inode_alloc", SharedMap}, // for all inodes
	}

	KprobeRenameMaps = []MapInfo{
		{"file_rename_map", SharedMap},
		{"execve_map", BaseMap},
		{"policy_filter_maps", BaseMap},
		{"buffer_heap_map", PrivateMap}, // for d_path_local
		{"tg_conf_map", BaseMap},
		{"tg_cgtracker_map", BaseMap},
		{"vfs_rename_info_heap", SharedMap},
		{"vr_retprobe_map", SharedMap},
		{"rename_retprobe_map", SharedMap},
	}

	KretprobeRenameMaps = []MapInfo{
		{"tcpmon_map", BaseMap},
		{"tg_stats_map", BaseMap},
		{"file_rename_heap_map", PrivateMap},
		{"file_errors_map", SharedMap}, // for eBPF errors
		{"file_config_map", SharedMap},
		{"file_val_map", PrivateMap},
		{"hash_map_inode_alloc", SharedMap}, // for all inodes
		{"lpm_trie_heap_key", PrivateMap},
		{"lpm_trie_map_alloc", SharedMap},
		{"patterns_map_alloc", SharedMap},
		{"rename_retprobe_map", SharedMap},
		{"vr_retprobe_map", SharedMap},
		{"exact_match_map_alloc", SharedMap},
	}

	KprobeSecurityPathRenameMaps = []MapInfo{
		{"file_errors_map", SharedMap}, // for eBPF errors
		{"rename_retprobe_map", SharedMap},
		{"spr_retprobe_map", SharedMap},
		{"vfs_rename_info_heap", SharedMap},
	}

	KretprobeSecurityPathRenameMaps = []MapInfo{
		{"file_errors_map", SharedMap}, // for eBPF errors
		{"rename_retprobe_map", SharedMap},
		{"spr_retprobe_map", SharedMap},
	}

	RWMiscMaps = []MapInfo{
		{"io_uring_map", SharedMap},   // for io_uring process information
		{"file_heap_map", PrivateMap}, // for struct msg_file_ops
	}

	MiscMaps = []MapInfo{
		{"file_heap_map", PrivateMap}, // for struct msg_file_ops
	}

	MiscLinkMaps = []MapInfo{
		{"file_link_heap_map", PrivateMap}, // for struct msg_file_link_ops
	}

	MiscSymlinkMaps = []MapInfo{
		{"file_symlink_heap_map", PrivateMap}, // for struct msg_file_link_ops
	}

	CreateInodeMiscMaps = []MapInfo{
		{"lpm_trie_heap_key", PrivateMap},
		{"lpm_trie_map_alloc", SharedMap},
		{"patterns_map_alloc", SharedMap},
		{"fsnotify_created_files_map", SharedMap},
		{"exact_match_map_alloc", SharedMap},
		{"buffer_heap_map", PrivateMap}, // for d_path_local
		{"file_heap_map", PrivateMap},   // for struct msg_file_ops
		{"file_val_map", PrivateMap},
	}

	SecurityFileOpenMaps = []MapInfo{
		{"file_heap_map", PrivateMap},   // for struct msg_file_ops
		{"buffer_heap_map", PrivateMap}, // for d_path_local
		{"exact_match_map_alloc", SharedMap},
		{"lpm_trie_heap_key", PrivateMap},
		{"lpm_trie_map_alloc", SharedMap},
		{"patterns_map_alloc", SharedMap},
		{"file_open_flags_map", SharedMap}, // for matchOpenFlags
		{".rodata.str1.1", SkipMap},
	}

	SecurityInodeLinkMaps = []MapInfo{
		{"file_heap_map", PrivateMap},   // for struct msg_file_ops
		{"buffer_heap_map", PrivateMap}, // for d_path_local
		{"exact_match_map_alloc", SharedMap},
		{"file_val_map", PrivateMap},
		{"lpm_trie_heap_key", PrivateMap},
		{"lpm_trie_map_alloc", SharedMap},
		{"patterns_map_alloc", SharedMap},
	}

	SecurityInodeCreateMaps = []MapInfo{
		{"file_heap_map", PrivateMap}, // for struct msg_file_ops
		{"lpm_trie_heap_key", PrivateMap},
		{"lpm_trie_map_alloc", SharedMap},
		{"patterns_map_alloc", SharedMap},
		{"exact_match_map_alloc", SharedMap},
		{"hash_map_inode_alloc", SharedMap}, // for all inodes
		{"file_config_map", SharedMap},      // for configuration options
		{"buffer_heap_map", PrivateMap},     // for d_path_local
	}

	SecurityInodeRenameMaps = []MapInfo{
		{"file_config_map", SharedMap},       // for configuration options
		{"file_errors_map", SharedMap},       // for eBPF errors
		{"file_rename_heap_map", PrivateMap}, // for struct msg_file_rename_ops
		{"rename_retprobe_map", SharedMap},
		{"tcpmon_map", BaseMap},
		{"tg_stats_map", BaseMap},
	}

	SecurityInodeMkdirMaps = []MapInfo{
		{"file_errors_map", SharedMap}, // for eBPF errors
		{"file_heap_map", PrivateMap},  // for struct msg_file_ops
		{"mkdir_retprobe_map", SharedMap},
		{"tcpmon_map", BaseMap},
		{"tg_stats_map", BaseMap},
	}

	PathBasedTailCallMaps = []MapInfo{
		{"fim_tail_calls", SharedMap},
		{"dis_ctx_heap", SharedMap},
		{"policy_id_to_tail_index", SharedMap},
	}

	// These programs are based on bpf_d_path helper to get the file path. bpf_d_path is introduced in kernel 5.10 (https://github.com/torvalds/linux/commit/6e22ab9da79343532cd3cde39df25e5a5478c692).
	// On the other hand, support for bpf_d_path helper is not introduced in 5.10 for all the following programs. We try to use bpf_d_path when it is available otherwise, we use our d_path_local helper.
	// For now we only support path-based hooks in kernels >= 5.17 (where bpf_loop helper is available https://github.com/torvalds/linux/commit/e6f2dd0f80674e9d5960337b3e9c2a242441b326) as in older kernels
	// there are complexity issues.
	FimPathBasedHooks = [...]FimHook{
		// security_file_permission is not part of sleepable_lsm_hooks (https://elixir.bootlin.com/linux/v6.9.8/source/kernel/bpf/bpf_lsm.c#L260) at the time of writing.
		// This means that this is the only program where bpf_d_path helper is not supported in lsm. For this reason we use fmod_ret progs (and not fentry to provide enforcement).
		// security_file_permission is part of the btf_allowlist_d_path since kernel 5.10 (https://github.com/torvalds/linux/commit/a8a717963fe5ecfd274eb93dd1285ee9428ffca7).
		// Use probeDpathSecurityFilePermission to check support for that.
		{"fmod_ret", "security_file_permission", []FimFunc{{"security_file_permission(struct file*, int)", "fmod_security_file_permission.o", "security_file_permission", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], RWMiscMaps[:], PathBasedTailCallMaps[:]}}}},
		// security_kernel_read_file is part of sleepable_lsm_hooks since kernel 5.18 (https://github.com/torvalds/linux/commit/df6b3039fa112e17555776213cab7f07c0a8d98d).
		// Use probeDpathSecurityKernelReadFile to check support for that.
		{"lsm", "security_kernel_read_file", []FimFunc{{"security_kernel_read_file(struct file*, enum kernel_read_file_id, bool)", "lsm_security_kernel_read_file.o", "kernel_read_file", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], RWMiscMaps[:], PathBasedTailCallMaps[:]}}}},
		// security_file_open, security_mmap_file, and security_bprm_check are part of sleepable_lsm_hooks since kernel 5.11 (https://github.com/torvalds/linux/commit/423f16108c9d832bd96059d5c882c8ef6d76eb96).
		// Use probeDpathSecurityFileOpen to check support for that.
		{"lsm", "security_file_open", []FimFunc{{"security_file_open(struct file*)", "lsm_security_file_open.o", "file_open", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], MiscMaps[:], PathBasedTailCallMaps[:]}}}},
		{"lsm", "security_mmap_file", []FimFunc{{"security_mmap_file(struct file*, int, int)", "lsm_security_mmap_file.o", "mmap_file", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], RWMiscMaps[:], PathBasedTailCallMaps[:]}}}},
		// security_path_* became part of sleepable_lsm_hooks in kernel 6.8 (https://github.com/torvalds/linux/commit/b13cddf633562b9b2c34fd63471d377019704ebe).
		// Use probeDpathSecurityPathTruncate to check support for that.
		{"lsm", "security_path_link", []FimFunc{{"security_path_link(struct dentry*, const struct path*, struct dentry*)", "lsm_security_path_link.o", "path_link", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], MiscLinkMaps[:], PathBasedTailCallMaps[:]}}}},
		{"lsm", "security_path_mkdir", []FimFunc{{"security_path_mkdir(const struct path*, struct dentry*, umode_t)", "lsm_security_path_mkdir.o", "path_mkdir", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], MiscMaps[:], PathBasedTailCallMaps[:]}}}},
		{"lsm", "security_path_rmdir", []FimFunc{{"security_path_rmdir(const struct path*, struct dentry*)", "lsm_security_path_rmdir.o", "path_rmdir", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], MiscMaps[:], PathBasedTailCallMaps[:]}}}},
		{"lsm", "security_path_unlink", []FimFunc{{"security_path_unlink(const struct path*, struct dentry*)", "lsm_security_path_unlink.o", "path_unlink", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], MiscMaps[:], PathBasedTailCallMaps[:]}}}},
		{"lsm", "security_path_truncate", []FimFunc{{"security_path_truncate(const struct path*)", "lsm_security_path_truncate.o", "path_truncate", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], MiscMaps[:], PathBasedTailCallMaps[:]}}}},
		{"lsm", "security_path_chmod", []FimFunc{{"security_path_chmod(const struct path*, umode_t)", "lsm_security_path_chmod.o", "path_chmod", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], MiscMaps[:], PathBasedTailCallMaps[:]}}}},
		{"lsm", "security_path_chown", []FimFunc{{"security_path_chown(const struct path*, kuid_t, kgid_t)", "lsm_security_path_chown.o", "path_chown", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], MiscMaps[:], PathBasedTailCallMaps[:]}}}},
		{"lsm", "security_path_rename", []FimFunc{{"security_path_rename(const struct path*, struct dentry*, const struct path*, struct dentry*, int)", "lsm_security_path_rename.o", "path_rename", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], {{"file_rename_heap_map", PrivateMap}}, {{"rename_path_heap", PrivateMap}}, PathBasedTailCallMaps[:]}}}},
		{"lsm", "security_path_symlink", []FimFunc{{"security_path_symlink(const struct path*, struct dentry*, const int*)", "lsm_security_path_symlink.o", "path_symlink", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], MiscSymlinkMaps[:], PathBasedTailCallMaps[:]}}}},
		{"fexit", "io_openat2", []FimFunc{{"int io_openat2(struct io_kiocb*, int)", "fexit_sys_open.o", "io_openat2", [][]MapInfo{{{"file_errors_map", SharedMap}}, {{"file_openraw_result_map", SharedMap}}, {{"file_openraw_heap_map", PrivateMap}}, {{"file_config_map", SharedMap}}, {{"buffer_heap_map", PrivateMap}}, PathBasedSelectorMaps[:], BaseMaps[:]}}}},
	}

	FimPathBasedGetnameHook = FimHook{"fexit", "getname", []FimFunc{{"struct filename* getname(const int*)", "fexit_getname.o", "getname", [][]MapInfo{{{"open_user_to_kernel_path", SharedMap}}, {{"kpath_heap", PrivateMap}}}}}}

	FimPathBasedGetnameFlagsHook = FimHook{"fexit", "getname_flags", []FimFunc{{"struct filename* getname_flags(const int*, int)", "fexit_getname_flags.o", "getname_flags", [][]MapInfo{{{"open_user_to_kernel_path", SharedMap}}, {{"kpath_heap", PrivateMap}}}}}}

	FimPathBasedTailCallHooks = [...]FimHook{
		{"fmod_ret", "tail_call", []FimFunc{{"", "fmod_security_file_permission.o", "security_file_permission", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], RWMiscMaps[:], PathBasedTailCallMaps[:]}}}},
		{"lsm", "tail_call", []FimFunc{{"", "lsm_security_kernel_read_file.o", "kernel_read_file", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], RWMiscMaps[:], PathBasedTailCallMaps[:]}}}},
		{"lsm", "tail_call", []FimFunc{{"", "lsm_security_file_open.o", "file_open", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], MiscMaps[:], PathBasedTailCallMaps[:]}}}},
		{"lsm", "tail_call", []FimFunc{{"", "lsm_security_mmap_file.o", "mmap_file", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], RWMiscMaps[:], PathBasedTailCallMaps[:]}}}},
		{"lsm", "tail_call", []FimFunc{{"", "lsm_security_path_link.o", "path_link", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], MiscLinkMaps[:], PathBasedTailCallMaps[:]}}}},
		{"lsm", "tail_call", []FimFunc{{"", "lsm_security_path_mkdir.o", "path_mkdir", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], MiscMaps[:], PathBasedTailCallMaps[:]}}}},
		{"lsm", "tail_call", []FimFunc{{"", "lsm_security_path_rmdir.o", "path_rmdir", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], MiscMaps[:], PathBasedTailCallMaps[:]}}}},
		{"lsm", "tail_call", []FimFunc{{"", "lsm_security_path_unlink.o", "path_unlink", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], MiscMaps[:], PathBasedTailCallMaps[:]}}}},
		{"lsm", "tail_call", []FimFunc{{"", "lsm_security_path_truncate.o", "path_truncate", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], MiscMaps[:], PathBasedTailCallMaps[:]}}}},
		{"lsm", "tail_call", []FimFunc{{"", "lsm_security_path_chmod.o", "path_chmod", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], MiscMaps[:], PathBasedTailCallMaps[:]}}}},
		{"lsm", "tail_call", []FimFunc{{"", "lsm_security_path_chown.o", "path_chown", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], MiscMaps[:], PathBasedTailCallMaps[:]}}}},
		{"lsm", "tail_call", []FimFunc{{"", "lsm_security_path_rename.o", "path_rename", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], {{"file_rename_heap_map", PrivateMap}}, {{"rename_path_heap", PrivateMap}}, PathBasedTailCallMaps[:]}}}},
		{"lsm", "tail_call", []FimFunc{{"", "lsm_security_path_symlink.o", "path_symlink", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], MiscSymlinkMaps[:], PathBasedTailCallMaps[:]}}}},
	}

	FimPathBasedHooksExec = FimHook{"lsm", "security_bprm_check", []FimFunc{{"security_bprm_check(struct linux_binprm*)", "lsm_security_bprm_check.o", "bprm_check_security", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], MiscMaps[:], PathBasedTailCallMaps[:]}}}}

	FimPathBasedTailCallHooksExec = FimHook{"lsm", "tail_call", []FimFunc{{"", "lsm_security_bprm_check.o", "bprm_check_security", [][]MapInfo{PathBasedSelectorMaps[:], BaseMaps[:], SkipMaps[:], PathBasedMiscMaps[:], MiscMaps[:], PathBasedTailCallMaps[:]}}}}

	FimPathBasedHooksExecDigests = [...]FimHook{
		{"lsm.s", "security_bprm_check", []FimFunc{{"security_bprm_check(struct linux_binprm*)", "lsm_security_bprm_check_digests.o", "bprm_check_security",
			[][]MapInfo{
				PathBasedSelectorMaps[:],
				SkipMaps[:],
				PathBasedMiscMaps[:],
				MiscMaps[:],
				{{"execve_map", BaseMap}},
				{{"policy_filter_maps", BaseMap}},
				{{"tg_conf_map", BaseMap}},
				{{"tg_cgtracker_map", BaseMap}},
				{{"exec_retprobe_map", SharedMap}},
				{{"file_digests_maps", SharedMap}},
				{{"digest_key_heap", PrivateMap}},
			},
		}}},
		{"fexit", "security_bprm_check", []FimFunc{{"int security_bprm_check(struct linux_binprm*)", "lsm_security_bprm_check_digests.o", "security_bprm_check",
			[][]MapInfo{
				{{"tcpmon_map", BaseMap}},
				{{"tg_stats_map", BaseMap}},
				{{"exec_retprobe_map", SharedMap}},
			},
		}}},
	}

	FimHooksObserve = [...]FimHook{
		{"kprobe", "vfs_fallocate", []FimFunc{{"vfs_fallocate(struct file*, int, loff_t, loff_t)", "bpf_vfs_fallocate.o", "vfs_fallocate", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], RWMiscMaps[:]}}}},
		{"kprobe", "filemap_fault", []FimFunc{{"filemap_fault(struct vm_fault*)", "bpf_filemap_fault.o", "filemap_fault", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], RWMiscMaps[:]}}}},
		{"kprobe", "filemap_map_pages", []FimFunc{{"filemap_map_pages(struct vm_fault*, int, int)", "bpf_filemap_map_pages.o", "filemap_map_pages", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], RWMiscMaps[:]}}}},
		{"kprobe", "filemap_page_mkwrite", []FimFunc{{"filemap_page_mkwrite(struct vm_fault*)", "bpf_filemap_page_mkwrite.o", "filemap_page_mkwrite", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], RWMiscMaps[:]}}}},
		{"kprobe", "security_file_permission", []FimFunc{{"security_file_permission(struct file*, int)", "bpf_security_file_permission.o", "security_file_permission", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], RWMiscMaps[:]}}}},
		{"kprobe", "vfs_unlink", []FimFunc{
			{"vfs_unlink(struct inode*, struct dentry*, struct inode**)", "bpf_vfs_unlink.o", "vfs_unlink/419", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:], InodeStatsMap[:]}},
			{"vfs_unlink(struct user_namespace*, struct inode*, struct dentry*, struct inode**)", "bpf_vfs_unlink.o", "vfs_unlink/512", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:], InodeStatsMap[:]}},
			{"vfs_unlink(struct mnt_idmap*, struct inode*, struct dentry*, struct inode**)", "bpf_vfs_unlink.o", "vfs_unlink/63", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:], InodeStatsMap[:]}},
		}},
		{"kprobe", "security_inode_rmdir", []FimFunc{{"security_inode_rmdir(struct inode*, struct dentry*)", "bpf_security_inode_rmdir.o", "security_inode_rmdir", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:], InodeStatsMap[:]}}}},
		{"kprobe", "vfs_mkdir", []FimFunc{
			{"vfs_mkdir(struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/419", [][]MapInfo{InodeBasedSelectorMaps[:], InodeBasedMiscMaps[:], KprobeMkdirMaps[:]}},
			{"vfs_mkdir(struct user_namespace*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/512", [][]MapInfo{InodeBasedSelectorMaps[:], InodeBasedMiscMaps[:], KprobeMkdirMaps[:]}},
			{"vfs_mkdir(struct mnt_idmap*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/63", [][]MapInfo{InodeBasedSelectorMaps[:], InodeBasedMiscMaps[:], KprobeMkdirMaps[:]}},
		}},
		{"kretprobe", "vfs_mkdir", []FimFunc{
			{"int vfs_mkdir(struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir", [][]MapInfo{KretprobeMkdirMaps[:], InodeStatsMap[:]}},
			{"int vfs_mkdir(struct user_namespace*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir", [][]MapInfo{KretprobeMkdirMaps[:], InodeStatsMap[:]}},
			{"int vfs_mkdir(struct mnt_idmap*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir", [][]MapInfo{KretprobeMkdirMaps[:], InodeStatsMap[:]}},
			{"struct dentry* vfs_mkdir(struct mnt_idmap*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/614", [][]MapInfo{KretprobeMkdirMaps[:], InodeStatsMap[:]}},
		}},
		{"kprobe", "security_path_rename", []FimFunc{{"security_path_rename(const struct path*, struct dentry*, const struct path*, struct dentry*, int)", "bpf_security_path_rename.o", "security_path_rename", [][]MapInfo{KprobeSecurityPathRenameMaps[:]}}}},
		{"kretprobe", "security_path_rename", []FimFunc{{"int security_path_rename(const struct path*, struct dentry*, const struct path*, struct dentry*, int)", "bpf_security_path_rename.o", "security_path_rename", [][]MapInfo{KretprobeSecurityPathRenameMaps[:]}}}},
		{"kprobe", "vfs_rename", []FimFunc{
			{"vfs_rename(struct inode*, struct dentry*, struct inode*, struct dentry*, struct inode**, int)", "bpf_vfs_rename.o", "vfs_rename/419", [][]MapInfo{InodeBasedSelectorMaps[:], InodeBasedMiscMaps[:], KprobeRenameMaps[:]}},
			{"vfs_rename(struct renamedata*)", "bpf_vfs_rename.o", "vfs_rename/512", [][]MapInfo{InodeBasedSelectorMaps[:], InodeBasedMiscMaps[:], KprobeRenameMaps[:]}},
		}},
		{"kretprobe", "vfs_rename", []FimFunc{
			{"int vfs_rename(struct inode*, struct dentry*, struct inode*, struct dentry*, struct inode**, int)", "bpf_vfs_rename.o", "vfs_rename", [][]MapInfo{KretprobeRenameMaps[:], InodeStatsMap[:]}},
			{"int vfs_rename(struct renamedata*)", "bpf_vfs_rename.o", "vfs_rename", [][]MapInfo{KretprobeRenameMaps[:], InodeStatsMap[:]}},
		}},
		{"kprobe", "iterate_dir", []FimFunc{{"iterate_dir(struct file*, struct dir_context*)", "bpf_iterate_dir.o", "iterate_dir", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:]}}}},
		{"kprobe", "security_inode_setattr", []FimFunc{
			{"security_inode_setattr(struct dentry*, struct iattr*)", "bpf_security_inode_setattr.o", "security_inode_setattr/419", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:]}},
			{"security_inode_setattr(struct user_namespace*, struct dentry*, struct iattr*)", "bpf_security_inode_setattr.o", "security_inode_setattr/60", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:]}},
			{"security_inode_setattr(struct mnt_idmap*, struct dentry*, struct iattr*)", "bpf_security_inode_setattr.o", "security_inode_setattr/63", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:]}},
		}},
		{"kprobe", "security_inode_link", []FimFunc{{"security_inode_link(struct dentry*, struct inode*, struct dentry*)", "bpf_security_inode_link.o", "security_inode_link", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], SecurityInodeLinkMaps[:], InodeStatsMap[:]}}}},
		{"kprobe", "security_file_open", []FimFunc{{"security_file_open(struct file*)", "bpf_security_file_open.o", "security_file_open", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], SecurityFileOpenMaps[:]}}}},
	}

	FimHooksObserveExec = FimHook{"kprobe", "security_bprm_check", []FimFunc{{"security_bprm_check(struct linux_binprm*)", "bpf_security_bprm_check.o", "security_bprm_check", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:], {{"exec_attributes_map", SharedMap}}}}}}

	FimHooksFmodRet = [...]FimHook{
		{"fmod_ret", "security_mmap_file", []FimFunc{{"security_mmap_file(struct file*, int, int)", "bpf_security_mmap_file_fmod.o", "security_mmap_file", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], RWMiscMaps[:]}}}},
		{"fmod_ret", "security_file_permission", []FimFunc{{"security_file_permission(struct file*, int)", "bpf_security_file_permission_enforce_fmod.o", "security_file_permission", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], RWMiscMaps[:]}}}},
		{"fmod_ret", "security_inode_unlink", []FimFunc{{"security_inode_unlink(struct inode*, struct dentry*)", "bpf_vfs_unlink_enforce_fmod.o", "security_inode_unlink", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:], InodeStatsMap[:]}}}},
		{"fmod_ret", "security_inode_create", []FimFunc{{"security_inode_create(struct inode*, struct dentry*, umode_t)", "bpf_security_inode_create_fmod.o", "security_inode_create", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], SecurityInodeCreateMaps[:]}}}},
		{"fmod_ret", "security_inode_rmdir", []FimFunc{{"security_inode_rmdir(struct inode*, struct dentry*)", "bpf_security_inode_rmdir_enforce_fmod.o", "security_inode_rmdir", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:], InodeStatsMap[:]}}}},
		{"kprobe", "vfs_mkdir", []FimFunc{
			{"vfs_mkdir(struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/419", [][]MapInfo{InodeBasedSelectorMaps[:], InodeBasedMiscMaps[:], KprobeMkdirMaps[:]}},
			{"vfs_mkdir(struct user_namespace*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/512", [][]MapInfo{InodeBasedSelectorMaps[:], InodeBasedMiscMaps[:], KprobeMkdirMaps[:]}},
			{"vfs_mkdir(struct mnt_idmap*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/63", [][]MapInfo{InodeBasedSelectorMaps[:], InodeBasedMiscMaps[:], KprobeMkdirMaps[:]}},
		}},
		{"kretprobe", "vfs_mkdir", []FimFunc{
			{"int vfs_mkdir(struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir", [][]MapInfo{KretprobeMkdirMaps[:], InodeStatsMap[:]}},
			{"int vfs_mkdir(struct user_namespace*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir", [][]MapInfo{KretprobeMkdirMaps[:], InodeStatsMap[:]}},
			{"int vfs_mkdir(struct mnt_idmap*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir", [][]MapInfo{KretprobeMkdirMaps[:], InodeStatsMap[:]}},
			{"struct dentry* vfs_mkdir(struct mnt_idmap*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/614", [][]MapInfo{KretprobeMkdirMaps[:], InodeStatsMap[:]}},
		}},
		{"fmod_ret", "security_inode_mkdir", []FimFunc{{"security_inode_mkdir(struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir_enforce_fmod.o", "security_inode_mkdir", [][]MapInfo{SecurityInodeMkdirMaps[:]}}}},
		{"kprobe", "security_path_rename", []FimFunc{{"security_path_rename(const struct path*, struct dentry*, const struct path*, struct dentry*, int)", "bpf_security_path_rename.o", "security_path_rename", [][]MapInfo{KprobeSecurityPathRenameMaps[:]}}}},
		{"kretprobe", "security_path_rename", []FimFunc{{"int security_path_rename(const struct path*, struct dentry*, const struct path*, struct dentry*, int)", "bpf_security_path_rename.o", "security_path_rename", [][]MapInfo{KretprobeSecurityPathRenameMaps[:]}}}},
		{"kprobe", "vfs_rename", []FimFunc{
			{"vfs_rename(struct inode*, struct dentry*, struct inode*, struct dentry*, struct inode**, int)", "bpf_vfs_rename.o", "vfs_rename/419", [][]MapInfo{InodeBasedSelectorMaps[:], InodeBasedMiscMaps[:], KprobeRenameMaps[:]}},
			{"vfs_rename(struct renamedata*)", "bpf_vfs_rename.o", "vfs_rename/512", [][]MapInfo{InodeBasedSelectorMaps[:], InodeBasedMiscMaps[:], KprobeRenameMaps[:]}},
		}},
		{"kretprobe", "vfs_rename", []FimFunc{
			{"int vfs_rename(struct inode*, struct dentry*, struct inode*, struct dentry*, struct inode**, int)", "bpf_vfs_rename.o", "vfs_rename", [][]MapInfo{KretprobeRenameMaps[:], InodeStatsMap[:]}},
			{"int vfs_rename(struct renamedata*)", "bpf_vfs_rename.o", "vfs_rename", [][]MapInfo{KretprobeRenameMaps[:], InodeStatsMap[:]}},
		}},
		{"fmod_ret", "security_inode_rename", []FimFunc{{"security_inode_rename(struct inode*, struct dentry*, struct inode*, struct dentry*, int)", "bpf_vfs_rename_enforce_fmod.o", "security_inode_rename", [][]MapInfo{SecurityInodeRenameMaps[:]}}}},
		{"fmod_ret", "security_file_permission", []FimFunc{{"security_file_permission(struct file*, int)", "bpf_iterate_dir_enforce_fmod.o", "security_file_permission", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:]}}}},
		{"fmod_ret", "security_inode_setattr", []FimFunc{
			{"security_inode_setattr(struct dentry*, struct iattr*)", "bpf_security_inode_setattr_enforce_fmod.o", "security_inode_setattr", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:]}},
			{"security_inode_setattr(struct user_namespace*, struct dentry*, struct iattr*)", "bpf_security_inode_setattr_enforce_fmod_v60.o", "security_inode_setattr", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:]}},
			{"security_inode_setattr(struct mnt_idmap*, struct dentry*, struct iattr*)", "bpf_security_inode_setattr_enforce_fmod_v63.o", "security_inode_setattr", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:]}},
		}},
		{"fmod_ret", "security_inode_link", []FimFunc{{"security_inode_link(struct dentry*, struct inode*, struct dentry*)", "bpf_security_inode_link_enforce_fmod.o", "security_inode_link", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], SecurityInodeLinkMaps[:], InodeStatsMap[:]}}}},
		{"fmod_ret", "security_file_open", []FimFunc{{"security_file_open(struct file*)", "bpf_security_file_open_enforce_fmod.o", "security_file_open", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], SecurityFileOpenMaps[:]}}}},
	}

	FimHooksFmodRetExec = FimHook{"fmod_ret", "security_bprm_check", []FimFunc{{"security_bprm_check(struct linux_binprm*)", "bpf_security_bprm_check_enforce_fmod.o", "security_bprm_check", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:], {{"exec_attributes_map", SharedMap}}}}}}

	FimHooksLsm = [...]FimHook{
		{"lsm", "security_mmap_file", []FimFunc{{"security_mmap_file(struct file*, int, int)", "bpf_security_mmap_file_lsm.o", "mmap_file", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], RWMiscMaps[:]}}}},
		{"lsm", "security_file_permission", []FimFunc{{"security_file_permission(struct file*, int)", "bpf_security_file_permission_enforce_lsm.o", "file_permission", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], RWMiscMaps[:]}}}},
		{"lsm", "security_inode_unlink", []FimFunc{{"security_inode_unlink(struct inode*, struct dentry*)", "bpf_vfs_unlink_enforce_lsm.o", "inode_unlink", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:], InodeStatsMap[:]}}}},
		{"lsm", "security_inode_create", []FimFunc{{"security_inode_create(struct inode*, struct dentry*, umode_t)", "bpf_security_inode_create_lsm.o", "inode_create", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], SecurityInodeCreateMaps[:]}}}},
		{"lsm", "security_inode_rmdir", []FimFunc{{"security_inode_rmdir(struct inode*, struct dentry*)", "bpf_security_inode_rmdir_enforce_lsm.o", "inode_rmdir", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:], InodeStatsMap[:]}}}},
		{"kprobe", "vfs_mkdir", []FimFunc{
			{"vfs_mkdir(struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/419", [][]MapInfo{InodeBasedSelectorMaps[:], InodeBasedMiscMaps[:], KprobeMkdirMaps[:]}},
			{"vfs_mkdir(struct user_namespace*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/512", [][]MapInfo{InodeBasedSelectorMaps[:], InodeBasedMiscMaps[:], KprobeMkdirMaps[:]}},
			{"vfs_mkdir(struct mnt_idmap*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/63", [][]MapInfo{InodeBasedSelectorMaps[:], InodeBasedMiscMaps[:], KprobeMkdirMaps[:]}},
		}},
		{"kretprobe", "vfs_mkdir", []FimFunc{
			{"int vfs_mkdir(struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir", [][]MapInfo{KretprobeMkdirMaps[:], InodeStatsMap[:]}},
			{"int vfs_mkdir(struct user_namespace*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir", [][]MapInfo{KretprobeMkdirMaps[:], InodeStatsMap[:]}},
			{"int vfs_mkdir(struct mnt_idmap*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir", [][]MapInfo{KretprobeMkdirMaps[:], InodeStatsMap[:]}},
			{"struct dentry* vfs_mkdir(struct mnt_idmap*, struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir.o", "vfs_mkdir/614", [][]MapInfo{KretprobeMkdirMaps[:], InodeStatsMap[:]}},
		}},
		{"lsm", "security_inode_mkdir", []FimFunc{{"security_inode_mkdir(struct inode*, struct dentry*, umode_t)", "bpf_vfs_mkdir_enforce_lsm.o", "inode_mkdir", [][]MapInfo{SecurityInodeMkdirMaps[:]}}}},
		{"kprobe", "security_path_rename", []FimFunc{{"security_path_rename(const struct path*, struct dentry*, const struct path*, struct dentry*, int)", "bpf_security_path_rename.o", "security_path_rename", [][]MapInfo{KprobeSecurityPathRenameMaps[:]}}}},
		{"kretprobe", "security_path_rename", []FimFunc{{"int security_path_rename(const struct path*, struct dentry*, const struct path*, struct dentry*, int)", "bpf_security_path_rename.o", "security_path_rename", [][]MapInfo{KretprobeSecurityPathRenameMaps[:]}}}},
		{"kprobe", "vfs_rename", []FimFunc{
			{"vfs_rename(struct inode*, struct dentry*, struct inode*, struct dentry*, struct inode**, int)", "bpf_vfs_rename.o", "vfs_rename/419", [][]MapInfo{InodeBasedSelectorMaps[:], InodeBasedMiscMaps[:], KprobeRenameMaps[:]}},
			{"vfs_rename(struct renamedata*)", "bpf_vfs_rename.o", "vfs_rename/512", [][]MapInfo{InodeBasedSelectorMaps[:], InodeBasedMiscMaps[:], KprobeRenameMaps[:]}},
		}},
		{"kretprobe", "vfs_rename", []FimFunc{
			{"int vfs_rename(struct inode*, struct dentry*, struct inode*, struct dentry*, struct inode**, int)", "bpf_vfs_rename.o", "vfs_rename", [][]MapInfo{KretprobeRenameMaps[:], InodeStatsMap[:]}},
			{"int vfs_rename(struct renamedata*)", "bpf_vfs_rename.o", "vfs_rename", [][]MapInfo{KretprobeRenameMaps[:], InodeStatsMap[:]}},
		}},
		{"lsm", "security_inode_rename", []FimFunc{{"security_inode_rename(struct inode*, struct dentry*, struct inode*, struct dentry*, int)", "bpf_vfs_rename_enforce_lsm.o", "inode_rename", [][]MapInfo{SecurityInodeRenameMaps[:]}}}},
		{"lsm", "security_file_permission", []FimFunc{{"security_file_permission(struct file*, int)", "bpf_iterate_dir_enforce_lsm.o", "file_permission", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:]}}}},
		{"lsm", "security_inode_setattr", []FimFunc{
			{"security_inode_setattr(struct dentry*, struct iattr*)", "bpf_security_inode_setattr_enforce_lsm.o", "inode_setattr", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:]}},
			{"security_inode_setattr(struct user_namespace*, struct dentry*, struct iattr*)", "bpf_security_inode_setattr_enforce_lsm.o", "inode_setattr", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:]}},
			{"security_inode_setattr(struct mnt_idmap*, struct dentry*, struct iattr*)", "bpf_security_inode_setattr_enforce_lsm.o", "inode_setattr", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:]}},
		}},
		{"lsm", "security_inode_link", []FimFunc{{"security_inode_link(struct dentry*, struct inode*, struct dentry*)", "bpf_security_inode_link_enforce_lsm.o", "inode_link", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], SecurityInodeLinkMaps[:], InodeStatsMap[:]}}}},
		{"lsm", "security_file_open", []FimFunc{{"security_file_open(struct file*)", "bpf_security_file_open_enforce_lsm.o", "file_open", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], SecurityFileOpenMaps[:]}}}},
	}

	FimHooksLsmExec = FimHook{"lsm", "security_bprm_check", []FimFunc{{"security_bprm_check(struct linux_binprm*)", "bpf_security_bprm_check_enforce_lsm.o", "bprm_check_security", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], MiscMaps[:], {{"exec_attributes_map", SharedMap}}}}}}

	FimHooksLsmExecDigests = [...]FimHook{
		{"lsm.s", "security_bprm_check", []FimFunc{{"security_bprm_check(struct linux_binprm*)", "bpf_security_bprm_check_enforce_lsm_digest.o", "bprm_check_security", [][]MapInfo{
			InodeBasedSelectorMaps[:],
			InodeBasedMiscMaps[:],
			MiscMaps[:],
			{{"execve_map", BaseMap}},
			{{"policy_filter_maps", BaseMap}},
			{{"tg_conf_map", BaseMap}},
			{{"tg_cgtracker_map", BaseMap}},
			{{"exec_retprobe_map", SharedMap}},
			{{"file_digests_maps", SharedMap}},
			{{"digest_key_heap", PrivateMap}},
			{{"exec_attributes_map", SharedMap}},
		}}}},
		{"fexit", "security_bprm_check", []FimFunc{{"int security_bprm_check(struct linux_binprm*)", "bpf_security_bprm_check_enforce_lsm_digest.o", "security_bprm_check", [][]MapInfo{
			{{"tcpmon_map", BaseMap}},
			{{"tg_stats_map", BaseMap}},
			{{"exec_retprobe_map", SharedMap}},
			{{"file_errors_map", SharedMap}},
		}}}},
	}

	FimIoUringHooks = [...]FimHook{
		{"kprobe", "io_read", []FimFunc{
			{"io_read(struct io_kiocb*, int)", "bpf_io_uring.o", "io_read/510", [][]MapInfo{IoUringMaps[:]}},
			{"io_read(struct io_kiocb*, bool, struct io_comp_state*)", "bpf_io_uring.o", "io_read/59", [][]MapInfo{IoUringMaps[:]}},
			{"io_read(struct io_kiocb*, bool)", "bpf_io_uring.o", "io_read/57", [][]MapInfo{IoUringMaps[:]}},
			{"io_read(struct io_kiocb*, struct io_kiocb**, bool)", "bpf_io_uring.o", "io_read/55", [][]MapInfo{IoUringMaps[:]}},
			{"io_read(struct io_kiocb*, const struct sqe_submit*, bool)", "bpf_io_uring.o", "io_read/51", [][]MapInfo{IoUringMaps[:]}},
		}},
		{"kretprobe", "io_read", []FimFunc{
			{"int io_read(struct io_kiocb*, int)", "bpf_io_uring.o", "io_read", [][]MapInfo{IoUringMaps[:]}},
			{"int io_read(struct io_kiocb*, bool, struct io_comp_state*)", "bpf_io_uring.o", "io_read", [][]MapInfo{IoUringMaps[:]}},
			{"int io_read(struct io_kiocb*, bool)", "bpf_io_uring.o", "io_read", [][]MapInfo{IoUringMaps[:]}},
			{"int io_read(struct io_kiocb*, struct io_kiocb**, bool)", "bpf_io_uring.o", "io_read", [][]MapInfo{IoUringMaps[:]}},
			{"int io_read(struct io_kiocb*, const struct sqe_submit*, bool)", "bpf_io_uring.o", "io_read", [][]MapInfo{IoUringMaps[:]}},
		}},
		{"kprobe", "io_write", []FimFunc{
			{"io_write(struct io_kiocb*, int)", "bpf_io_uring.o", "io_write/510", [][]MapInfo{IoUringMaps[:]}},
			{"io_write(struct io_kiocb*, bool, struct io_comp_state*)", "bpf_io_uring.o", "io_write/59", [][]MapInfo{IoUringMaps[:]}},
			{"io_write(struct io_kiocb*, bool)", "bpf_io_uring.o", "io_write/57", [][]MapInfo{IoUringMaps[:]}},
			{"io_write(struct io_kiocb*, struct io_kiocb**, bool)", "bpf_io_uring.o", "io_write/55", [][]MapInfo{IoUringMaps[:]}},
			{"io_write(struct io_kiocb*, const struct sqe_submit*, bool)", "bpf_io_uring.o", "io_write/51", [][]MapInfo{IoUringMaps[:]}},
		}},
		{"kretprobe", "io_write", []FimFunc{
			{"int io_write(struct io_kiocb*, int)", "bpf_io_uring.o", "io_write", [][]MapInfo{IoUringMaps[:]}},
			{"int io_write(struct io_kiocb*, bool, struct io_comp_state*)", "bpf_io_uring.o", "io_write", [][]MapInfo{IoUringMaps[:]}},
			{"int io_write(struct io_kiocb*, bool)", "bpf_io_uring.o", "io_write", [][]MapInfo{IoUringMaps[:]}},
			{"int io_write(struct io_kiocb*, struct io_kiocb**, bool)", "bpf_io_uring.o", "io_write", [][]MapInfo{IoUringMaps[:]}},
			{"int io_write(struct io_kiocb*, const struct sqe_submit*, bool)", "bpf_io_uring.o", "io_write", [][]MapInfo{IoUringMaps[:]}},
		}},
	}

	FimIoUringSingleHooks = [...]FimHook{
		{"kprobe", "io_issue_sqe", []FimFunc{{"io_issue_sqe(struct io_kiocb*, int)", "bpf_io_uring.o", "io_issue_sqe", [][]MapInfo{IoUringMaps[:]}}}},
		{"kretprobe", "io_issue_sqe", []FimFunc{{"int io_issue_sqe(struct io_kiocb*, int)", "bpf_io_uring.o", "io_issue_sqe", [][]MapInfo{IoUringMaps[:]}}}},
	}

	FimHooksFileCreate = [...]FimHook{
		{"kprobe", "finish_open", []FimFunc{{"finish_open(struct file*, struct dentry*, int (*p)(struct inode*, struct file*))", "bpf_finish_open.o", "finish_open", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], CreateInodeMiscMaps[:], InodeStatsMap[:]}}}},
		{"kprobe", "vfs_open", []FimFunc{{"vfs_open(const struct path*, struct file*)", "bpf_vfs_open.o", "vfs_open", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], CreateInodeMiscMaps[:], InodeStatsMap[:]}}}},
	}

	FimHooksFileCreate418 = [...]FimHook{
		{"kprobe", "finish_open", []FimFunc{{"finish_open(struct file*, struct dentry*, int (*p)(struct inode*, struct file*), int*)", "bpf_finish_open.o", "finish_open", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], CreateInodeMiscMaps[:], InodeStatsMap[:]}}}},
		{"kprobe", "vfs_open", []FimFunc{{"vfs_open(const struct path*, struct file*)", "bpf_vfs_open.o", "vfs_open", [][]MapInfo{InodeBasedSelectorMaps[:], BaseMaps[:], InodeBasedMiscMaps[:], CreateInodeMiscMaps[:], InodeStatsMap[:]}}}},
		{"kprobe", "fsnotify", []FimFunc{{"fsnotify(struct inode*, __u32, const void*, int, const struct qstr*, u32)", "bpf_fsnotify.o", "fsnotify", [][]MapInfo{{{"fsnotify_created_files_map", SharedMap}}, {{"file_errors_map", SharedMap}}}}}},
	}
)

func TerminateFsScanner() error {
	client, err := rpc.Dial("unix", fm.ScannerFifoPath)
	if err != nil {
		filemetrics.FileTotalErrorsInc(filemetrics.SensorFileRPCTerminate)
		return err
	}
	defer client.Close()

	if err := client.Call("FsScannerRpc.Terminate", struct{}{}, &struct{}{}); err != nil {
		return err
	}

	// wait for fifo to be removed
	retry := 0
	for {
		if _, err := os.Stat(fm.ScannerFifoPath); err != nil {
			break
		}
		if retry > 10 {
			logger.GetLogger().Warnf("Failed to wait for fifo to be removed")
			break
		}
		time.Sleep(time.Second)
		retry++
	}

	fsScannerCmd = nil

	return killFsScanner() // to cleanup leftovers in the case of failures
}

func TracingPolicyInitFsScanner(tpName string, s v1alpha1.FileSpec, m string, pin string, addToMaps bool) (map[fileapi.InodeKey]fileapi.InodeVal, error) {
	// no need to send a message to fs-scanner for path-based policies
	if m, _, err := GetTpMode(&s); err == nil && m != InodeBasedTpMode {
		return make(map[fileapi.InodeKey]fileapi.InodeVal), nil
	}

	f := fm.FsScannerInit{
		PolicyName: tpName,
		Spec:       s,
		MapDir:     m,
		PinPath:    pin,
		AddToMaps:  addToMaps,
	}

	client, err := rpc.Dial("unix", fm.ScannerFifoPath)
	if err != nil {
		filemetrics.FileTotalErrorsInc(filemetrics.SensorFileRPCInitHost)
		return nil, fmt.Errorf("failed filemetrics.FileTotalErrorsInc: %w", err)
	}
	defer client.Close()

	reply := make(map[fileapi.InodeKey]fileapi.InodeVal)
	if err := client.Call("FsScannerRpc.TracingPolicyInit", &f, &reply); err != nil {
		return nil, fmt.Errorf("failed FsScannerRpc.TracingPolicyInit: %w", err)
	}
	return reply, nil
}

func TracingPolicyPathDigestsFsScanner(s v1alpha1.FileSpec, sel *fm.KernelSelectorState) (map[string]string, error) {
	// no need to send a message to fs-scanner for inode-based policies
	if m, _, err := GetTpMode(&s); err == nil && m != PathBasedTpMode {
		return make(map[string]string), nil
	}

	// no need to send a message to fs-scanner if there are no file that we need digests
	paths := sel.GetDigestPaths()
	if len(paths) == 0 {
		return make(map[string]string), nil
	}

	algo, err := probeImaEnabled()
	if err != nil {
		return nil, fmt.Errorf("failed to probe IMA: %w", err)
	}

	algoNum, ok := tetragon.DigestAlgo_value[algo]
	if !ok {
		return nil, fmt.Errorf("invalid digest algorithm: %s", algo)
	}

	f := fm.FsScannerDigests{
		Algo:  algoNum,
		Files: paths,
	}

	client, err := rpc.Dial("unix", fm.ScannerFifoPath)
	if err != nil {
		filemetrics.FileTotalErrorsInc(filemetrics.SensorFileRPCInitHost)
		return nil, fmt.Errorf("failed filemetrics.FileTotalErrorsInc: %w", err)
	}
	defer client.Close()

	reply := make(map[string]string)
	if err := client.Call("FsScannerRpc.TracingPolicyFileDigests", &f, &reply); err != nil {
		return nil, fmt.Errorf("failed FsScannerRpc.TracingPolicyFileDigests: %w", err)
	}
	return reply, nil
}

func TracingPolicyPathDigestsContainerFsScanner(specPath []fm.SpecPinPath, containerID, podNs, podName, rootDir string, addToMaps bool) (map[string]string, error) {
	if len(specPath) == 1 {
		spec := specPath[0].Spec
		// no need to send a message to fs-scanner for inode-based policies
		if m, _, err := GetTpMode(&spec); err == nil && m != PathBasedTpMode {
			return make(map[string]string), nil
		}
	} else if len(specPath) == 0 {
		for _, s := range pol.FileMonitoringTable.GetValuesFIM() {
			if m, _, err := GetTpMode(&s.Spec); err == nil && m != PathBasedTpMode {
				continue
			}
			// no need to send a message to fs-scanner if there are no file that we need digests
			if len(s.DigestPaths) == 0 {
				continue
			}
			specPath = append(specPath, s)
		}
		// none of the tracing policies are path-based, no need to send a message to fs-scanner
		if len(specPath) == 0 {
			return make(map[string]string), nil
		}
	}

	algo, err := probeImaEnabled()
	if err != nil {
		return nil, fmt.Errorf("failed to probe IMA: %w", err)
	}

	algoNum, ok := tetragon.DigestAlgo_value[algo]
	if !ok {
		return nil, fmt.Errorf("invalid digest algorithm: %s", algo)
	}

	f := fm.FsScannerContainerDigests{
		Algo:        algoNum,
		Tp:          specPath,
		ContainerID: containerID,
		MapDir:      option.Config.BpfDir,
		PodNs:       podNs,
		PodName:     podName,
		RootDir:     rootDir,
		AddToMaps:   addToMaps,
	}

	client, err := rpc.Dial("unix", fm.ScannerFifoPath)
	if err != nil {
		filemetrics.FileTotalErrorsInc(filemetrics.SensorFileRPCInitCont)
		return nil, fmt.Errorf("failed filemetrics.FileTotalErrorsInc: %w", err)
	}
	defer client.Close()

	reply := make(map[string]string)
	if err := client.Call("FsScannerRpc.TracingPolicyContainerFileDigests", &f, &reply); err != nil {
		return nil, fmt.Errorf("failed FsScannerRpc.TracingPolicyContainerFileDigests: %w", err)
	}
	return reply, nil
}

func RenameFsScanner(path, mapDir, pinPath, cId, polName string, spec v1alpha1.FileSpec, flags uint32) (int64, error) {
	// no need to send a message to fs-scanner for path-based policies
	if m, _, err := GetTpMode(&spec); err == nil && m != InodeBasedTpMode {
		return 0, nil
	}

	f := fm.FsScannerRename{
		WalkPath:    path,
		MapDir:      mapDir,
		PinPath:     pinPath,
		ContainerID: cId,
		Spec:        spec,
		PolicyName:  polName,
		Flags:       flags,
	}
	var reply fm.FsScannerRenameReply

	client, err := rpc.Dial("unix", fm.ScannerFifoPath)
	if err != nil {
		filemetrics.FileTotalErrorsInc(filemetrics.SensorFileRPCScanner)
		return 0, err
	}
	defer client.Close()

	err = client.Call("FsScannerRpc.RenameDir", &f, &reply)
	return reply.Diff, err
}

func TracingPolicyInitContainerFsScanner(specPath []fm.SpecPinPath, containerID, podNs, podName, rootDir string, addToMaps bool) (map[fileapi.InodeKey]fileapi.InodeVal, error) {
	if len(specPath) == 1 {
		spec := specPath[0].Spec
		// no need to send a message to fs-scanner for path-based policies
		if m, _, err := GetTpMode(&spec); err == nil && m != InodeBasedTpMode {
			return make(map[fileapi.InodeKey]fileapi.InodeVal), nil
		}
	} else if len(specPath) == 0 {
		for _, s := range pol.FileMonitoringTable.GetValuesFIM() {
			if m, _, err := GetTpMode(&s.Spec); err == nil && m == InodeBasedTpMode {
				specPath = append(specPath, s)
			}
		}
		// none of the tracing policies are path-based, no need to send a message to fs-scanner
		if len(specPath) == 0 {
			return make(map[fileapi.InodeKey]fileapi.InodeVal), nil
		}
	}
	f := fm.FsScannerContainerInit{
		Tp:          specPath,
		MapDir:      option.Config.BpfDir,
		ContainerID: containerID,
		PodNs:       podNs,
		PodName:     podName,
		RootDir:     rootDir,
		AddToMaps:   addToMaps,
	}

	client, err := rpc.Dial("unix", fm.ScannerFifoPath)
	if err != nil {
		filemetrics.FileTotalErrorsInc(filemetrics.SensorFileRPCInitCont)
		return nil, err
	}
	defer client.Close()

	reply := make(map[fileapi.InodeKey]fileapi.InodeVal)
	if err := client.Call("FsScannerRpc.TracingPolicyContainerInit", &f, &reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func TracingPolicyDestroyContainerFsScanner(containerID string) error {
	specPath := pol.FileMonitoringTable.GetValuesFIM()
	f := fm.FsScannerContainerDestroy{
		Tp:          specPath,
		MapDir:      option.Config.BpfDir,
		ContainerID: containerID,
	}

	client, err := rpc.Dial("unix", fm.ScannerFifoPath)
	if err != nil {
		filemetrics.FileTotalErrorsInc(filemetrics.SensorFileRPCDestroyCont)
		return err
	}
	defer client.Close()

	return client.Call("FsScannerRpc.TracingPolicyContainerDestroy", &f, &struct{}{})
}

func checkRunningFsScanner(scannerFifo string) error {
	matches, err := filepath.Glob("/proc/*/exe")
	if err != nil {
		return fmt.Errorf("checkRunningFsScanner: %w", err)
	}

	for _, file := range matches {
		target, _ := os.Readlink(file)
		if len(target) > 0 && strings.Contains(target, "tetragon-fs-scanner") {
			logger.GetLogger().Warn("Found a running instance of tetragon-fs-scanner on clean start. Killing it.")
			exec.Command("killall", "-9", "tetragon-fs-scanner").Run()
			break
		}
	}

	// There is a case where fs-scanner is killed and the FIFO is not removed. Remove that here just to be sure.
	os.Remove(scannerFifo)

	return nil
}

func startFsScanner() (*exec.Cmd, error) {
	if fm.ScannerFifoPath == "" {
		if option.Config.EnableK8s {
			fm.ScannerFifoPath = path.Join(eeOption.Config.FimFifoPath, fm.ScannerFifoName)
		} else {
			fm.ScannerFifoPath = path.Join(eeOption.Config.FimFifoLocalPath, fm.ScannerFifoName)
		}
	}

	execName := path.Join(option.Config.HubbleLib, "tetragon-fs-scanner")
	execFd, err := os.Open(execName)
	if err != nil {
		return nil, fmt.Errorf("startFsScanner: failed to open %s: %w", execName, err)
	}
	defer execFd.Close()

	mntNsId, err := namespace.GetPidNsInode(1, "mnt")
	if err != nil {
		return nil, fmt.Errorf("startFsScanner: failed to get host mnt namespace: %w", err)
	}
	args := []string{
		fmt.Sprintf("%s/1/ns/mnt", option.Config.ProcFS),
		execName,
		"-hostMntNs", strconv.FormatUint(uint64(mntNsId), 10),
		"-scannerFifoPath", fm.ScannerFifoPath,
		"-maxSizeFileDigest", strconv.FormatInt(eeOption.Config.FimMaxFileSizeDigest, 10),
		"-maxTimeoutFileDigest", strconv.FormatInt(eeOption.Config.FimMaxTimeoutDigestSec, 10),
	}

	if option.Config.Debug {
		args = append(args, "-debug")
	}

	if eeOption.Config.FimRuntimeEndpoint != "" {
		args = append(args, "-runtimeEndpoint", eeOption.Config.FimRuntimeEndpoint)
	}

	level, levelOk := option.Config.LogOpts["level"]
	if levelOk {
		args = append(args, "-logLevel", level)
	}

	format, formatOk := option.Config.LogOpts["format"]
	if formatOk {
		args = append(args, "-logFormat", format)
	}

	// After an agent crash, tetragon-fs-scanner may be still running.
	// This is the point of a clean start, so we expect no fs-scanner running
	// or the FIFO to exist. We do this check and cleanup appropriately if needed.
	if err := checkRunningFsScanner(fm.ScannerFifoPath); err != nil {
		logger.GetLogger().WithError(err).Warn("checkRunningFsScanner fails")
	}

	ctx, cancel := context.WithCancel(context.Background())
	fsScannerCmd := exec.CommandContext(ctx, path.Join(option.Config.HubbleLib, "tetragon-runner"), args...)
	fsScannerCancelFnMtx.Lock()
	fsScannerCancelFn = cancel
	fsScannerCancelFnMtx.Unlock()

	logger.GetLogger().WithField("args", fsScannerCmd.Args).Info("Agent starting")

	fsScannerCmd.Env = append(fsScannerCmd.Env, fmt.Sprintf("TETRAGON_PROCFS=%s", option.Config.ProcFS))
	fsScannerCmd.Stdout = os.Stdout
	fsScannerCmd.Stderr = os.Stderr
	fsScannerCmd.ExtraFiles = []*os.File{execFd}

	if err := fsScannerCmd.Start(); err != nil {
		return nil, fmt.Errorf("fsScannerCmd.Start(): %w", err)
	}

	// wait for fifo to appear
	retry := 0
	for {
		if _, err := os.Stat(fm.ScannerFifoPath); err == nil {
			break
		}
		if retry > 10 {
			return nil, fmt.Errorf("failed to start tetragon-fs-scanner")
		}
		logger.GetLogger().Infof("tetragon-fs-scanner fifo does not exist [retry = %d]", retry)
		time.Sleep(2 * time.Second)
		retry++
	}

	// We should wait here for the process to stop. Otherwise the FsScanner becomes a zombie.
	go func() {
		if err := fsScannerCmd.Wait(); err != nil {
			logger.GetLogger().WithError(err).Warnf("fsScannerCmd.Wait(): failed with '%s'", err)
		}
	}()

	return fsScannerCmd, nil
}

func killFsScanner() error {
	fsScannerCancelFnMtx.Lock()
	if fsScannerCancelFn != nil {
		fsScannerCancelFn()
		fsScannerCancelFn = nil
	}
	fsScannerCancelFnMtx.Unlock()

	// remove the fifo (if any)
	os.Remove(fm.ScannerFifoPath)

	return nil
}

type observerFileSensor struct {
	name string
}

func init() {
	file := &observerFileSensor{
		name: "file sensor",
	}
	sensors.RegisterProbeType("file_monitoring", file)
	sensors.RegisterPolicyHandlerAtInit(file.name, file)

	observer.RegisterEventHandlerAtInit(ops.MSG_OP_FILE, handleFileOps)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_FILE_RENAME, handleFileRenameOps)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_FILE_LINK, handleFileLinkOps)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_FILE_SYMLINK, handleFileSymlinkOps)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_FILE_OPENRAW, handleFileOpenrawOps)
	rthooks.RegisterCallbacksAtInit(rthooks.Callbacks{
		CreateContainer: rthooksCreateContainer,
	})
	podhooks.RegisterCallbacksAtInit(podhooks.Callbacks{
		PodCallbacks: func(podInformer cache.SharedIndexInformer) {
			podInformer.AddEventHandler(
				cache.ResourceEventHandlerFuncs{
					AddFunc:    podhooksAddFunc,
					UpdateFunc: podhooksUpdateFunc,
					DeleteFunc: podhooksDeleteFunc,
				},
			)
		},
	})
}

func createFsInfoUnix(fs fileapi.MsgFsInfo) file.MsgFsInfoUnix {
	uuid_str := "<failed to parse uuid>"
	u, err := uuid.FromBytes(fs.SUuid[:])
	if err == nil {
		if u == uuid.Nil {
			uuid_str = "" // avoid printing UUID full of 0s
		} else {
			uuid_str = u.String()
		}
	}
	sidIndex := bytes.IndexByte(fs.SId[:], 0)
	snameIndex := bytes.IndexByte(fs.SName[:], 0)

	sid := "error"
	if sidIndex > -1 {
		sid = string(fs.SId[:sidIndex])
	}

	sname := "error"
	if snameIndex > -1 {
		sname = string(fs.SName[:snameIndex])
	}

	return file.MsgFsInfoUnix{
		SName: sname,
		SId:   sid,
		SUuid: uuid_str,
	}
}

func isFileExecEvent(action, hook uint32) bool {
	return action == 0xFFFFFFFF && hook == 0xFFFFFFFF
}

func handleFileOps(r *bytes.Reader) ([]observer.Event, error) {
	m := fileapi.MsgFileEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		filemetrics.FileTotalErrorsInc(filemetrics.SensorFileOp)
		return nil, fmt.Errorf("failed to read file operation: %w", err)
	}

	str := strutils.UTF8FromBPFBytes(m.Path.Str[:])
	if uint32(len(str)) > m.Path.Size {
		str = str[:m.Path.Size]
	}

	cid := ""
	if m.Path.Flags&fileapi.CONTAINER_FILE != 0 {
		cid = string(m.Path.ContainerID[:])
	}

	digest := file.MsgDigest{}
	if m.Digest.Ok == 1 {
		if digest.Error = m.Digest.Algo; digest.Error >= 0 { // we don't have an error here
			digestLen := fm.IMA_MAX_DIGEST_SIZE
			if dlen, ok := fm.HashAlgoLen[tetragon.DigestAlgo(m.Digest.Algo)]; ok {
				digestLen = dlen
			}
			for i := 0; i < digestLen; i++ {
				digest.Hash += fmt.Sprintf("%02x", m.Digest.Digest[i])
			}
			digest.Error = 0
		} else {
			// failed to get file digest
			if isFileExecEvent(m.Action, m.Hook) {
				filemetrics.FileFailedDigestInc(filemetrics.FileEventProcessExec)
			} else {
				filemetrics.FileFailedDigestInc(filemetrics.FileEventProcess)
			}
		}
	}

	unix := &file.MsgFileEventUnix{
		Msg:         &m,
		Path:        str,
		Fs:          createFsInfoUnix(m.Fs),
		ParentFs:    createFsInfoUnix(m.ParentFs),
		ContainerID: cid,
		TpName:      pol.FileMonitoringTable.GetTpName(m.TpId),
		TpRule:      pol.FileMonitoringTable.GetTpRule(m.TpId, m.RuleID),
		TpMessage:   pol.FileMonitoringTable.GetTpMessage(m.TpId, m.MessageId),
		Digest:      digest,
		OpenFlags:   m.OpenFlags,
	}

	return []observer.Event{unix}, nil
}

func handleFileLinkOps(r *bytes.Reader) ([]observer.Event, error) {
	m := fileapi.MsgFileLinkEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		filemetrics.FileTotalErrorsInc(filemetrics.SensorFileLink)
		return nil, fmt.Errorf("failed to read file link operation: %w", err)
	}

	targetStr := strutils.UTF8FromBPFBytes(m.Target.Path.Str[:])
	if uint32(len(targetStr)) > m.Target.Path.Size {
		targetStr = targetStr[:m.Target.Path.Size]
	}

	linkStr := strutils.UTF8FromBPFBytes(m.Link.Path.Str[:])
	if uint32(len(linkStr)) > m.Link.Path.Size {
		linkStr = linkStr[:m.Link.Path.Size]
	}

	unix := &file.MsgFileLinkEventUnix{
		Msg:            &m,
		TargetPath:     targetStr,
		TargetFs:       createFsInfoUnix(m.Target.Fs),
		TargetParentFs: createFsInfoUnix(m.Target.ParentFs),
		LinkPath:       linkStr,
		LinkFs:         createFsInfoUnix(m.Link.Fs),
		LinkParentFs:   createFsInfoUnix(m.Link.ParentFs),
		TpName:         pol.FileMonitoringTable.GetTpName(m.TpId),
		TpRule:         pol.FileMonitoringTable.GetTpRule(m.TpId, m.RuleID),
		TpMessage:      pol.FileMonitoringTable.GetTpMessage(m.TpId, m.MessageId),
	}

	return []observer.Event{unix}, nil
}

func handleFileSymlinkOps(r *bytes.Reader) ([]observer.Event, error) {
	m := fileapi.MsgFileSymlinkEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		filemetrics.FileTotalErrorsInc(filemetrics.SensorFileSymlink)
		return nil, fmt.Errorf("failed to read file symlink operation: %w", err)
	}

	linkStr := strutils.UTF8FromBPFBytes(m.Link.Path.Str[:])
	if uint32(len(linkStr)) > m.Link.Path.Size {
		linkStr = linkStr[:m.Link.Path.Size]
	}

	targetStr := strutils.UTF8FromBPFBytes(m.Target.Str[:])
	if uint32(len(targetStr)) > m.Target.Size {
		targetStr = targetStr[:m.Target.Size]
	}

	unix := &file.MsgFileSymlinkEventUnix{
		Msg:          &m,
		TargetPath:   targetStr,
		LinkPath:     linkStr,
		LinkFs:       createFsInfoUnix(m.Link.Fs),
		LinkParentFs: createFsInfoUnix(m.Link.ParentFs),
		TpName:       pol.FileMonitoringTable.GetTpName(m.TpId),
		TpRule:       pol.FileMonitoringTable.GetTpRule(m.TpId, m.RuleID),
		TpMessage:    pol.FileMonitoringTable.GetTpMessage(m.TpId, m.MessageId),
	}

	return []observer.Event{unix}, nil
}

func handleFileOpenrawOps(r *bytes.Reader) ([]observer.Event, error) {
	m := fileapi.MsgFileOpenRawEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		filemetrics.FileTotalErrorsInc(filemetrics.SensorFileOpenraw)
		return nil, fmt.Errorf("failed to read file openraw operation: %w", err)
	}

	openPath := strutils.UTF8FromBPFBytes(m.Path.Str[:])
	if uint32(len(openPath)) > m.Path.Size {
		openPath = openPath[:m.Path.Size]
	}

	retval := m.Retval
	if retval > 0 {
		retval = 0
	}
	retval = -retval

	unix := &file.MsgFileOpenrawEventUnix{
		Msg:       &m,
		Path:      openPath,
		Retval:    retval,
		TpName:    pol.FileMonitoringTable.GetTpName(m.TpId),
		TpRule:    pol.FileMonitoringTable.GetTpRule(m.TpId, m.RuleID),
		TpMessage: pol.FileMonitoringTable.GetTpMessage(m.TpId, m.MessageId),
	}

	if m.IsRelativePath != 0 {
		dirPath := strutils.UTF8FromBPFBytes(m.Dir.Str[:])
		if uint32(len(dirPath)) > m.Dir.Size {
			dirPath = dirPath[:m.Dir.Size]
		}
		unix.DirPath = dirPath
		unix.DirFs = createFsInfoUnix(m.DirFs)
	}

	return []observer.Event{unix}, nil
}

func hasFlag(flags, flag uint32) bool {
	return (flags & flag) != 0
}

func handleFileRenameOps(r *bytes.Reader) ([]observer.Event, error) {
	l := logger.GetLogger()
	m := fileapi.MsgFileRenameEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		filemetrics.FileTotalErrorsInc(filemetrics.SensorFileMv)
		return nil, fmt.Errorf("failed to read file operation: %w", err)
	}

	srcDir := strutils.UTF8FromBPFBytes(m.Src.Path.Dir[:])
	if m.Src.Path.DirSize == 0xffffffff { // due to missing security_path_rename
		srcDir = "/<UNRESOLVED>"
	} else if uint32(len(srcDir)) > m.Src.Path.DirSize {
		srcDir = srcDir[:m.Src.Path.DirSize]
	}

	srcName := strutils.UTF8FromBPFBytes(m.Src.Path.Name[:])
	if uint32(len(srcName)) > m.Src.Path.NameSize {
		srcName = srcName[:m.Src.Path.NameSize]
	}

	srcCid := ""
	if m.Src.Path.Flags&fileapi.CONTAINER_FILE != 0 {
		srcCid = string(m.Src.Path.ContainerID[:])
	}

	dstDir := strutils.UTF8FromBPFBytes(m.Dst.Path.Dir[:])
	if m.Dst.Path.DirSize == 0xffffffff { // due to missing security_path_rename
		srcDir = "/<UNRESOLVED>"
	} else if uint32(len(dstDir)) > m.Dst.Path.DirSize {
		dstDir = dstDir[:m.Dst.Path.DirSize]
	}

	dstName := strutils.UTF8FromBPFBytes(m.Dst.Path.Name[:])
	if uint32(len(dstName)) > m.Dst.Path.NameSize {
		dstName = dstName[:m.Dst.Path.NameSize]
	}

	dstCid := ""
	if m.Dst.Path.Flags&fileapi.CONTAINER_FILE != 0 {
		dstCid = string(m.Dst.Path.ContainerID[:])
	}

	if hasFlag(m.Flags, fm.SRC_DIRECTORY) {
		s, err := pol.FileMonitoringTable.GetFIM(m.TpId)
		if err != nil {
			filemetrics.FileTotalErrorsInc(filemetrics.SensorFileMvTcId)
			return nil, fmt.Errorf("failed to get fim table index: %w", err)
		}

		renameCid := ""
		if srcCid == "" && dstCid != "" { // use the non-empty
			renameCid = dstCid
		} else if srcCid != "" && dstCid == "" { // use the non-empty
			renameCid = srcCid
		} else if srcCid != "" && dstCid != "" { // both are non-empty
			renameCid = dstCid // both not empty -- use destination containerID
		}

		path := filepath.Join(dstDir, dstName)
		if diff, err := RenameFsScanner(path, option.Config.BpfDir, s.PinPathPrefix, renameCid, s.TpName, *s.Spec, m.Flags); err != nil {
			filemetrics.FileTotalErrorsInc(filemetrics.SensorFileMvScanner)
			l.WithError(err).Warnf("RenameFsScanner failed!")
		} else {
			atomic.AddInt64(&s.UserInodeNum, diff)
		}
	}

	// The following should not be possible to happen. If we catch any of these we should handle them
	// (not difficult to implement)
	if hasFlag(m.Flags, fm.SRC_DIRECTORY) {
		if hasFlag(m.Flags, fm.DST_REG_FILE) {
			if hasFlag(m.Flags, fm.MOVE_INSIDE) {
				l.Warnf("[NOOP][SRC_DIRECTORY - MOVE_INSIDE - DST_REG_FILE]")
			} else if hasFlag(m.Flags, fm.MOVE_OUTSIDE) {
				l.Warnf("[NOOP][SRC_DIRECTORY - MOVE_OUTSIDE - DST_REG_FILE]")
			} else if hasFlag(m.Flags, fm.MOVE_INTERNALLY) {
				l.Warnf("[NOOP][SRC_DIRECTORY - MOVE_INTERNALLY - DST_REG_FILE]")
			}
		}
	} else if hasFlag(m.Flags, fm.SRC_REG_FILE) {
		if hasFlag(m.Flags, fm.DST_DIRECTORY) {
			if hasFlag(m.Flags, fm.MOVE_INSIDE) {
				l.Warnf("[NOOP][SRC_REG_FILE - MOVE_INSIDE - DST_DIRECTORY]")
			} else if hasFlag(m.Flags, fm.MOVE_OUTSIDE) {
				l.Warnf("[NOOP][SRC_REG_FILE - MOVE_OUTSIDE - DST_DIRECTORY]")
			} else if hasFlag(m.Flags, fm.MOVE_INTERNALLY) {
				l.Warnf("[NOOP][SRC_REG_FILE - MOVE_INTERNALLY - DST_DIRECTORY]")
			}
		}
	}

	unix := &file.MsgFileRenameEventUnix{
		Msg: &m,
		Src: file.MsgRenameElemUnix{
			Path:        filepath.Join(srcDir, srcName),
			Fs:          createFsInfoUnix(m.Src.Fs),
			ParentFs:    createFsInfoUnix(m.Src.ParentFs),
			ContainerID: srcCid,
		},
		Dst: file.MsgRenameElemUnix{
			Path:        filepath.Join(dstDir, dstName),
			Fs:          createFsInfoUnix(m.Dst.Fs),
			ParentFs:    createFsInfoUnix(m.Dst.ParentFs),
			ContainerID: dstCid,
		},
		TpName:    pol.FileMonitoringTable.GetTpName(m.TpId),
		TpRule:    pol.FileMonitoringTable.GetTpRule(m.TpId, m.RuleID),
		TpMessage: pol.FileMonitoringTable.GetTpMessage(m.TpId, m.MessageId),
	}

	return []observer.Event{unix}, nil
}

func addFilter(handle *ebpf.Map, filter string, val fileapi.LPMMapValue) error {
	var k fileapi.LPMMapKey

	k.Prefixlen = uint32(len(filter)) * 8
	copy(k.Data[:], filter)

	var exKey fileapi.LPMMapKey
	var exVal fileapi.LPMMapValue
	entries := handle.Iterate()
	for entries.Next(&exKey, &exVal) {
		if k.Prefixlen == exKey.Prefixlen && k.Data == exKey.Data { // key already exists
			if exVal.Action == fm.FilterMatch {
				return nil
			}
		}
	}

	err := handle.Update(k, val, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed handle.Update: %w", err)
	}
	return nil
}

func addFilters(handle *ebpf.Map, str string, val fileapi.LPMMapValue) error {
	for { // iterate all path components
		if err := addFilter(handle, str, val); err != nil {
			return err
		}

		val = fileapi.LPMMapValue{Action: fm.FilterMonitor} // after the first iteration everything is in monitor state

		if str == "/" { // reached root fs - nothing more to do
			return nil
		}

		// remove the rightmost path component
		str, _ = filepath.Split(strings.TrimSuffix(str, "/"))
	}
}

func allocNewTailId(policyId uint32) (uint32, error) {
	for i := uint32(1); i < maxTailId; i++ {
		if _, ok := policyIdToTailId[i]; !ok {
			policyIdToTailId[i] = policyId
			return i, nil
		}
	}
	return 0, fmt.Errorf("allocNewTailId: Cannot allocate tail id for policy id %d", policyId)
}

func clearTailId(tailId uint32) {
	delete(policyIdToTailId, tailId)
}

type TailCallIndex struct {
	valid bool
	index uint32
}

type FimLoaderData struct {
	tp         string // type of program (i.e. kprobe, kretprobe, lsm, fmod_ret, etc.)
	progBpfDir string
	tail       TailCallIndex
	tailId     uint32
}

func addFileMonitoringSensor(policy tracingpolicy.TracingPolicy, kprobes v1alpha1.FileSpec, fimProgs []FimProg, config fileapi.FileConfigMapValue, sel *fm.KernelSelectorState, tpConf *configFileSensorOptions, pathMatcher PathBasedMatcher, mode TpMode) (*sensors.Sensor, error) {
	var progs []*program.Program
	var maps []*program.Map

	config.TpId = atomic.AddUint32(&pol.SensorCounter, 1)
	name := fmt.Sprintf("fim_sensor_%d", config.TpId)
	e := &pol.FileMonitoring{
		Spec:          &kprobes,
		PinPathPrefix: name,
		TpName:        policy.TpName(),
		TpRules:       make(map[int]string),
		TpMessages:    sel.GetMessagesMap(),
		Config:        &config,
		DigestPaths:   sel.GetDigestPaths(),
		PathMetadata:  sel.GetPathMetadata(),
		IsPathBased:   mode == PathBasedTpMode,
	}
	// Add rules from file_paths with a unique number assosciated to each of them.
	// No need to add file_paths_exclude as we will never get an event from these.
	for i, p := range kprobes.PathsPatterns {
		e.TpRules[i] = fm.PathPatternToString(p)
	}
	pol.FileMonitoringTable.AddFIM(config.TpId, e)

	l := logger.GetLogger()

	var tailId uint32
	if eeOption.Config.EnableFimDispatcher && config.PolicyId != 0 {
		var err error
		tailId, err = allocNewTailId(config.PolicyId)
		if err != nil {
			return nil, fmt.Errorf("addFileMonitoringSensor: %v", err)
		}

		var policyMap *ebpf.Map
		policyMapPinPath := path.Join(option.Config.BpfDir, baseFIMPolicy, "policy_id_to_tail_index")
		policyMap, err = ebpf.LoadPinnedMap(policyMapPinPath, nil)
		if err != nil {
			return nil, fmt.Errorf("addFileMonitoringSensor: ebpf.LoadPinnedMap fails for %s", policyMapPinPath)
		}
		defer policyMap.Close()

		// add a new entry into tail calls map
		err = policyMap.Update(config.PolicyId, tailId, ebpf.UpdateAny)
		if err != nil {
			return nil, fmt.Errorf("addFileMonitoringSensor: policyMap.Update fails for policy_id %d and tail_id %d: %v", config.PolicyId, tailId, err)
		}
	}

	exactFilePathMatch := make(map[string]uint32)
	config.NumPatterns = uint32(len(kprobes.PathsPatterns))
	for i, p := range kprobes.PathsPatterns {
		if p.Type == "FileExactMatch" {
			if strings.HasSuffix(p.FileExactMatch.Path, "/") {
				return nil, fmt.Errorf("file path for exact match cannot end with /: [%s]", p.FileExactMatch.Path)
			}
			exactFilePathMatch[p.FileExactMatch.Path] = uint32(i)
		}
	}

	t0 := time.Now()
	allInodes := make(map[fileapi.InodeKey]fileapi.InodeVal)
	allDigestMaps := make(map[string][]string) // map from path to list of acceptable digests

	if kprobes.MonitorHostFiles {
		hostInodes, err := TracingPolicyInitFsScanner(policy.TpName(), kprobes, option.Config.BpfDir, e.PinPathPrefix, false)
		if err != nil {
			filemetrics.FileTotalErrorsInc(filemetrics.SensorFileInitScanner)
			l.WithError(err).Warnf("TracingPolicyInitFsScanner failed!")
		} else {
			mapHelpers.Copy(allInodes, hostInodes)
		}

		digestMap, err := TracingPolicyPathDigestsFsScanner(kprobes, sel)
		if err != nil {
			filemetrics.FileTotalErrorsInc(filemetrics.SensorFileInitScanner)
			l.WithError(err).Warnf("TracingPolicyPathDigestsFsScanner failed!")
		} else {
			for k, v := range digestMap {
				if _, ok := allDigestMaps[k]; !ok {
					allDigestMaps[k] = []string{v}
				} else {
					allDigestMaps[k] = append(allDigestMaps[k], v)
				}
			}
		}
	}
	numHostInodes := len(allInodes)

	// check for existing pod files when we create a new tracing policy
	allContainers := []ContInit{}
	allPodsMu.Lock()
	for _, p := range allPods {
		for _, r := range p.containers {
			allContainers = append(allContainers, ContInit{
				cid:       r.ContainerID,
				namespace: p.podNamespace,
				name:      p.podName,
				root:      r.RootDir,
			})
		}
	}
	allPodsMu.Unlock()
	for _, i := range allContainers {
		s := fm.SpecPinPath{
			PolicyName:  policy.TpName(),
			PinPath:     e.PinPathPrefix,
			Spec:        kprobes,
			IsPathBased: mode == PathBasedTpMode,
		}

		containerInodes, err := TracingPolicyInitContainerFsScanner([]fm.SpecPinPath{s}, i.cid, i.namespace, i.name, i.root, false)
		if err != nil {
			filemetrics.FileTotalErrorsInc(filemetrics.SensorFileInitContainerScanner)
			logger.GetLogger().WithError(err).Warnf("TracingPolicyInitContainerFsScanner failed")
		} else {
			mapHelpers.Copy(allInodes, containerInodes)
		}

		s.DigestPaths = sel.GetDigestPaths()
		s.PathMetadata = sel.GetPathMetadata()
		digestMap, err := TracingPolicyPathDigestsContainerFsScanner([]fm.SpecPinPath{s}, i.cid, i.namespace, i.name, i.root, false)
		if err != nil {
			filemetrics.FileTotalErrorsInc(filemetrics.SensorFileInitContainerScanner)
			l.WithError(err).Warnf("TracingPolicyPathDigestsContainerFsScanner failed!")
		} else {
			for k, v := range digestMap {
				if _, ok := allDigestMaps[k]; !ok {
					allDigestMaps[k] = []string{v}
				} else {
					allDigestMaps[k] = append(allDigestMaps[k], v)
				}
			}
		}
	}

	logger.GetLogger().WithFields(logrus.Fields{
		"time":           time.Since(t0).String(),
		"total-inodes":   len(allInodes),
		"host-inodes":    numHostInodes,
		"num-pods":       len(allPods),
		"num-containers": len(allContainers),
	}).Infof("Completed path scanning for %s.", e.TpName)

	switch tpConf.watchedInodeMapSizePolicy {
	case "auto":
		config.MaxWatchedInodes = uint32(float32(len(allInodes))*tpConf.watchedInodeMapSizeMultiplier) + tpConf.watchedInodeMapSizeConstant
		logger.GetLogger().WithFields(logrus.Fields{
			"max-inode-map-size":      config.MaxWatchedInodes,
			"user-defined-multiplier": tpConf.watchedInodeMapSizeMultiplier,
			"user-defined-constant":   tpConf.watchedInodeMapSizeConstant,
		}).Infof("Using automatic map sizing for %s.", e.TpName)
	case "fixed":
		// first check if the fixed size is enough to start the sensor
		if uint32(len(allInodes)) >= tpConf.watchedInodeMapMaxiumSize {
			return nil, fmt.Errorf("the fixed size of inode map (%d) for files is not enough to start the sensor: %d", tpConf.watchedInodeMapMaxiumSize, len(allInodes))
		}
		config.MaxWatchedInodes = tpConf.watchedInodeMapMaxiumSize
		logger.GetLogger().WithFields(logrus.Fields{
			"max-inode-map-size": config.MaxWatchedInodes,
			"user-defined-size":  tpConf.watchedInodeMapMaxiumSize,
		}).Infof("Using fixed map sizing for %s.", e.TpName)
	default:
		return nil, fmt.Errorf("unknown watchedInodeMapSizePolicy: %s", tpConf.watchedInodeMapSizePolicy)
	}

	// set metric to maximum size of inode map for files
	filemetrics.FileSetInodeMapMax(e.TpName, float64(config.MaxWatchedInodes))

	// make sure that when we do not use the exact match
	// we sert the size of exact_match_map_alloc to 1, otherwise
	// it will fail to load the program.
	exactFilePathMatchSize := uint32(len(exactFilePathMatch))
	if exactFilePathMatchSize == 0 {
		exactFilePathMatchSize = 1
	}

	// count the number of entries with FileSystemType
	// to set the proper size of that map
	fileSystemTypes := make(map[string]uint32)
	for _, p := range kprobes.PathsPatterns {
		if p.Type == "FileSystemType" {
			for _, n := range p.FileSystemType.Names {
				nn := strings.ToLower(n)
				// check if this is a valid file system name
				if _, ok := fm.FsNameMagic[nn]; !ok {
					return nil, fmt.Errorf("file system name %s is not a valid option", n)
				}
				fileSystemTypes[nn] = uint32(0)
			}
		}
	}
	numFileSystemTypes := len(fileSystemTypes)
	if numFileSystemTypes == 0 {
		numFileSystemTypes = 1
	}

	maxSelectors := fm.MaxFimSelectors
	if mode == PathBasedTpMode {
		maxSelectors = fm.MaxFimGlobSelectors
	}

	// Make sure we have unique pinName in case some programs share the same hook,
	// adding extra unique number in case of conflict.
	pinMap := make(map[string]int)
	pinName := func(h FimProg) string {
		var pin string
		if h.name == "tail_call" {
			pin = fmt.Sprintf("%s_%s", h.tp, h.progSection)
		} else {
			pin = fmt.Sprintf("%s_%s", h.tp, h.name)
		}
		extra := pinMap[pin]
		pinMap[pin] = extra + 1
		if extra > 0 {
			if h.name == "tail_call" {
				pin = fmt.Sprintf("%s_%s_%d", h.tp, h.progSection, extra)
			} else {
				pin = fmt.Sprintf("%s_%s_%d", h.tp, h.name, extra)
			}
		}
		return pin
	}

	ovlSpec := probeOverlayModule()
	config.NumSelectors = sel.GetNumSelectors() // pass the total number of selectors
	for _, h := range fimProgs {
		load := program.Builder(
			path.Join(option.Config.HubbleLib, h.progName),
			h.name,
			fmt.Sprintf("%s/%s", h.tp, h.progSection),
			pinName(h),
			"file_monitoring")
		if h.tp == "kretprobe" {
			load = load.SetRetProbe(true)
		}
		load.SetLoaderData(FimLoaderData{
			tp:         h.tp,
			progBpfDir: strings.Join([]string{h.tp, h.progSection}, "_"),
			tailId:     tailId,
		})
		if ovlSpec != nil {
			load.KernelTypes = ovlSpec
		}

		var checkReWrite func() error
		switch h.progName {
		case "fmod_security_file_permission.o":
			checkReWrite = probeDpathSecurityFilePermission
		case "lsm_security_kernel_read_file.o":
			checkReWrite = probeDpathSecurityKernelReadFile
		case "lsm_security_file_open.o", "lsm_security_mmap_file.o", "lsm_security_bprm_check.o", "lsm_security_bprm_check_digests.o":
			checkReWrite = probeDpathSecurityFileOpen
		case "lsm_security_path_link.o", "lsm_security_path_symlink.o", "lsm_security_path_mkdir.o", "lsm_security_path_rmdir.o", "lsm_security_path_unlink.o", "lsm_security_path_truncate.o", "lsm_security_path_chmod.o", "lsm_security_path_chown.o", "lsm_security_path_rename.o":
			checkReWrite = probeDpathSecurityPathTruncate
		}
		if checkReWrite != nil {
			val := uint32(0)
			if checkReWrite() == nil {
				val = 1
			}
			load.RewriteConstants = map[string]interface{}{
				"USE_BPF_D_PATH_HELPER": uint32(val),
				// this applies to all path-based programs
				// so, we don't need to use a separate section for that
				"PATH_BASED_MATCHER": uint32(pathMatcher),
			}
		}

		progs = append(progs, load)

		for _, m := range h.maps {
			if m.tp == SkipMap || m.tp == PrivateMap || m.tp == BaseMap {
				// nothing to do on those type of maps
				continue
			}

			if m.name == "fim_tail_calls" || m.name == "policy_id_to_tail_index" || m.name == "dis_ctx_heap" {
				// we are not in a tail call program so just ignore those
				if h.name != "tail_call" {
					continue
				}

				switch m.name {
				case "policy_id_to_tail_index":
					load.PinMap[m.name] = PolicyIdToTailIndexMap
				case "dis_ctx_heap":
					load.PinMap[m.name] = DisCtxHeapMap
				case "fim_tail_calls":
					mp, ok := DisCallsMaps[fmt.Sprintf("%s/%s", h.tp, h.progSection)]
					if !ok {
						return nil, fmt.Errorf("addFileMonitoringSensor: Failed to find fim_tail_calls map for program %s", h.name)
					}
					load.PinMap[m.name] = mp
				}
				continue
			}

			// shared maps here
			m := program.MapBuilderPolicy(m.name, load)

			// custom max entries setup
			var loadMapFunc func(_ *ebpf.Map, _ string, _ uint32) error
			switch m.Name {
			case "tg_mb_paths":
				m.SetInnerMaxEntries(sel.MatchBinariesPathsMaxEntries())
				m.SetMaxEntries(maxSelectors)
				loadMapFunc = func(outerMap *ebpf.Map, pinPathPrefix string, _ uint32) error {
					return fm.PopulateMatchBinariesPathsMaps(sel, pinPathPrefix, outerMap)
				}
			case "tg_mb_sel_opts":
				m.SetMaxEntries(maxSelectors)
				loadMapFunc = func(outerMap *ebpf.Map, _ string, _ uint32) error {
					return fm.PopulateMatchBinariesMaps(sel, outerMap)
				}
			case "string_prefix_maps":
				loadMapFunc = func(m *ebpf.Map, pinPathPrefix string, _ uint32) error {
					if err := fm.PopulateStringPrefixFilterMaps(&sel.KernelSelectorState, pinPathPrefix, m); err != nil {
						return fmt.Errorf("file_ops_maps: %w", err)
					}
					return nil
				}
			case "string_postfix_maps":
				loadMapFunc = func(m *ebpf.Map, pinPathPrefix string, _ uint32) error {
					if err := fm.PopulateStringPostfixFilterMaps(&sel.KernelSelectorState, pinPathPrefix, m); err != nil {
						return fmt.Errorf("file_ops_maps: %w", err)
					}
					return nil
				}
			case "file_ops_maps":
				m.SetInnerMaxEntries(int(fm.GetMaxInnerEntriesOpsMap(sel)))
				m.SetMaxEntries(maxSelectors)
				loadMapFunc = func(m *ebpf.Map, pinPathPrefix string, _ uint32) error {
					if err := fm.GenerateFileOpsMap(m, sel, pinPathPrefix); err != nil {
						return fmt.Errorf("file_ops_maps: %w", err)
					}
					return nil
				}
			case "file_uidgid_map":
				m.SetMaxEntries(fm.GetUidGidMapSize(sel))
				loadMapFunc = func(m *ebpf.Map, _ string, _ uint32) error {
					if err := fm.GenerateUidGidMap(m, sel); err != nil {
						return fmt.Errorf("file_uidgid_map: %w", err)
					}
					return nil
				}
			case "file_proc_dur_map":
				m.SetMaxEntries(fm.GetProcessDurationMapSize(sel))
				loadMapFunc = func(m *ebpf.Map, _ string, _ uint32) error {
					if err := fm.GenerateProcessDurationMap(m, sel); err != nil {
						return fmt.Errorf("file_proc_dur_map: %w", err)
					}
					return nil
				}
			case "file_digests_maps":
				m.SetInnerMaxEntries(int(fm.GetMaxInnerEntriesDigestsMap(sel)))
				m.SetMaxEntries(maxSelectors)
				loadMapFunc = func(m *ebpf.Map, pinPathPrefix string, _ uint32) error {
					if err := fm.GenerateFileDigestsMap(m, sel, pinPathPrefix); err != nil {
						return fmt.Errorf("file_digests_maps: %w", err)
					}
					return nil
				}
			case "hash_map_inode_alloc":
				m.SetMaxEntries(int(config.MaxWatchedInodes))
				loadMapFunc = func(m *ebpf.Map, _ string, _ uint32) error {
					for k, v := range allInodes {
						if err := m.Update(k, v, 0); err != nil {
							return err
						}
					}
					return nil
				}
			case "exact_match_map_alloc":
				m.SetMaxEntries(int(exactFilePathMatchSize))
				loadMapFunc = func(m *ebpf.Map, _ string, _ uint32) error {
					for k, v := range exactFilePathMatch {
						key := fileapi.FullPath{}
						copy(key.Path[:], []byte(k))
						if err := m.Update(key, v, 0); err != nil {
							return err
						}
					}
					return nil
				}
			case "file_system_type_map":
				m.SetMaxEntries(numFileSystemTypes)
				loadMapFunc = func(m *ebpf.Map, _ string, _ uint32) error {
					for i, p := range kprobes.PathsPatterns {
						if p.Type == "FileSystemType" {
							for _, fsName := range p.FileSystemType.Names {
								key, ok := fm.FsNameMagic[strings.ToLower(fsName)]
								if !ok {
									return fmt.Errorf("file system name %s is not a valid option", fsName)
								}
								idx := uint32(i)
								if err := m.Update(&key, &idx, ebpf.UpdateAny); err != nil {
									return fmt.Errorf("failed to add FileSystemType in file_system_type_map: %w", err)
								}
							}
						}
					}
					return nil
				}
			case "file_actions_map":
				m.SetMaxEntries(maxSelectors)
				loadMapFunc = func(m *ebpf.Map, _ string, _ uint32) error {
					if err := fm.GenerateFileActionsMap(m, sel); err != nil {
						return fmt.Errorf("file_actions_map: %w", err)
					}
					return nil
				}
			case "file_namespaces_map":
				m.SetMaxEntries(maxSelectors)
				loadMapFunc = func(m *ebpf.Map, _ string, _ uint32) error {
					if err := fm.GenerateFileNamespacesMap(m, sel); err != nil {
						return fmt.Errorf("file_namespaces_map: %w", err)
					}
					return nil
				}
			case "file_capabilities_map":
				m.SetMaxEntries(maxSelectors)
				loadMapFunc = func(m *ebpf.Map, _ string, _ uint32) error {
					if err := fm.GenerateFileCapabilitiesMap(m, sel); err != nil {
						return fmt.Errorf("file_capabilities_map: %w", err)
					}
					return nil
				}
			case "glob_patterns_map":
				m.SetInnerMaxEntries(fm.GetMaxInnerEntriesPatternsMap(sel))
				loadMapFunc = func(m *ebpf.Map, _ string, _ uint32) error {
					if err := fm.GeneratePatternsMap(m, sel, e.PinPathPrefix); err != nil {
						return fmt.Errorf("glob_patterns_map: %w", err)
					}
					return nil
				}
			case "glob_temp_maps":
				m.SetInnerMaxEntries(128) // same as INNER_MAX_STATES in bpf_glob.h
				m.SetMaxEntries(2 * bpf.GetNumPossibleCPUs())
				loadMapFunc = func(m *ebpf.Map, _ string, _ uint32) error {
					for i := range 2 * bpf.GetNumPossibleCPUs() {
						innerName := fmt.Sprintf("glob_inner_%d", i)
						innerSpec := &ebpf.MapSpec{
							Name:       innerName,
							Type:       ebpf.Hash,
							KeySize:    4,
							ValueSize:  4,
							MaxEntries: 128,
						}
						innerMap, err := ebpf.NewMapWithOptions(innerSpec, ebpf.MapOptions{
							PinPath: sensors.PathJoin(e.PinPathPrefix, innerName),
						})
						if err != nil {
							return fmt.Errorf("creating innerMap %s failed: %w", innerName, err)
						}
						defer innerMap.Close()

						if err := m.Update(uint32(i), uint32(innerMap.FD()), 0); err != nil {
							return fmt.Errorf("failed to insert %s: %w", innerName, err)
						}
					}

					return nil
				}
			case "filename_ops_map":
				m.SetMaxEntries(fm.GetNumFilenameSelectors(sel))
				loadMapFunc = func(m *ebpf.Map, _ string, _ uint32) error {
					return fm.GenerateFilenameOpsMap(m, sel)
				}
			case "filename_path_map":
				m.SetMaxEntries(maxSelectors)
				m.SetInnerMaxEntries(fm.GetMaxInnerEntriesPathMap(sel))
				loadMapFunc = func(m *ebpf.Map, _ string, _ uint32) error {
					return fm.GeneratePathsMap(m, sel, e.PinPathPrefix)
				}
			case "file_openraw_result_map":
				m.SetMaxEntries(fm.GetOpenrawResultMapSize(sel))
				loadMapFunc = func(m *ebpf.Map, _ string, _ uint32) error {
					return fm.GenerateOpenrawResultMap(m, sel)
				}
			case "filename_digest_map":
				m.SetMaxEntries(maxSelectors)
				// how many digests can we have per path
				// i.e. /usr/bin/ls can have 1 digest in the host
				// and 1 digest each container that the policy matches
				// We choose to multiply the number of paths by 32 which
				// should be enough for most cases.
				// TODO: make this configurable
				m.SetInnerMaxEntries((fm.GetMaxInnerEntriesPathMap(sel) * 32))
				loadMapFunc = func(m *ebpf.Map, _ string, _ uint32) error {
					algo, err := probeImaEnabled()
					if err != nil {
						return fmt.Errorf("failed to probe IMA: %w", err)
					}
					algoNum, ok := tetragon.DigestAlgo_value[algo]
					if !ok {
						return fmt.Errorf("invalid digest algorithm: %s", algo)
					}
					return fm.GenerateDigestsMap(m, sel, e.PinPathPrefix, allDigestMaps, algoNum)
				}
			case "lpm_trie_map_alloc":
				loadMapFunc = func(m *ebpf.Map, _ string, _ uint32) error {
					for _, str := range kprobes.PathsExclude {
						if err := addFilters(m, str, fileapi.LPMMapValue{Action: fm.FilterIgnore}); err != nil {
							return fmt.Errorf("failed to add ExcludePath: %w", err)
						}
					}
					for i, p := range kprobes.PathsPatterns {
						switch p.Type {
						case "FilePrefixSuffix":
							if err := addFilters(m, p.FilePrefixSuffix.Prefix, fileapi.LPMMapValue{Action: fm.FilterMonitor, Rule: uint32(i)}); err != nil {
								return fmt.Errorf("failed to add PathPattern in lpm_trie_map_alloc: %w", err)
							}
						case "PathPrefix":
							if err := addFilters(m, p.PathPrefix.Prefix, fileapi.LPMMapValue{Action: fm.FilterMatch, Rule: uint32(i)}); err != nil {
								return fmt.Errorf("failed to add WatchPath: %w", err)
							}
						case "FileExactMatch":
							if err := addFilters(m, filepath.Dir(p.FileExactMatch.Path), fileapi.LPMMapValue{Action: fm.FilterMonitor, Rule: uint32(i)}); err != nil {
								return fmt.Errorf("failed to add PathPattern in lpm_trie_map_alloc: %w", err)
							}
						}
					}
					return nil
				}
			case "patterns_map_alloc":
				loadMapFunc = func(m *ebpf.Map, _ string, _ uint32) error {
					for i, p := range kprobes.PathsPatterns {
						if p.Type == "FilePrefixSuffix" {
							key := uint32(i)
							val := fileapi.PatternValue{
								PrefixLen: uint32(len(p.FilePrefixSuffix.Prefix)),
								SuffixLen: uint32(len(p.FilePrefixSuffix.Suffix)),
								Action:    fm.FilterMatch,
								Rule:      uint32(i),
							}

							if val.PrefixLen > 256 || val.SuffixLen > 128 {
								return fmt.Errorf("max prefix size is 256 characters and max suffix size is 128 characters: prefix:[%s], suffix:[%s]", p.FilePrefixSuffix.Prefix, p.FilePrefixSuffix.Suffix)
							}

							copy(val.Prefix[:], []byte(p.FilePrefixSuffix.Prefix))
							copy(val.Suffix[:], []byte(p.FilePrefixSuffix.Suffix))

							if err := m.Update(&key, &val, ebpf.UpdateAny); err != nil {
								return fmt.Errorf("failed to add PathPattern in patterns_map_alloc: %w", err)
							}
						}
					}
					return nil
				}
			case "file_rename_map":
				loadMapFunc = func(m *ebpf.Map, _ string, _ uint32) error {
					if err := fm.GenerateFileRenameMap(m, sel); err != nil {
						return fmt.Errorf("file_rename_map: %w", err)
					}
					return nil
				}
			case "exec_attributes_map":
				loadMapFunc = func(m *ebpf.Map, _ string, _ uint32) error {
					if err := fm.GenerateFileExecAttrs(m, sel); err != nil {
						return fmt.Errorf("exec_attributes_map: %w", err)
					}
					return nil
				}
			case "file_open_flags_map":
				m.SetMaxEntries(maxSelectors)
				m.SetInnerMaxEntries(fm.MaxOpenFlagMaskPerOp)
				loadMapFunc = func(m *ebpf.Map, pinPathPrefix string, _ uint32) error {
					if err := fm.GenerateFileOpenFlagsMap(m, sel, pinPathPrefix); err != nil {
						return fmt.Errorf("file_open_flags_map: %w", err)
					}
					return nil
				}
			case "file_config_map":
				loadMapFunc = func(m *ebpf.Map, _ string, _ uint32) error {
					return m.Update(uint32(0), config, ebpf.UpdateAny)
				}
			case "hash_map_inode_alloc_stats":
				loadMapFunc = func(m *ebpf.Map, _ string, _ uint32) error {
					return m.Update(uint32(0), []int64{int64(len(allInodes))}, ebpf.UpdateAny)
				}
			}

			// use a load func if needed
			if loadMapFunc != nil {
				load.MapLoad = append(load.MapLoad, &program.MapLoad{
					Index: 0,
					Name:  m.Name,
					Load:  loadMapFunc,
				})
			}

			// add this map to the list of maps
			maps = append(maps, m)
		}

		if option.Config.EnableCgTrackerID {
			maps = append(maps, program.MapUser(cgtracker.MapName, load))
		}
	}

	maps = append(maps, program.MapUserFrom(base.ExecveMap))

	return &sensors.Sensor{
		Name:   name,
		Progs:  progs,
		Maps:   maps,
		Policy: policy.TpName(),
		PostLoadHook: func() error {
			clear(allInodes)
			allInodes = nil
			return nil
		},
		PreUnloadHook: func() error {
			if eeOption.Config.EnableFimDispatcher && config.PolicyId != 0 {
				clearTailId(tailId)
			}
			pol.FileMonitoringTable.RmFIM(config.TpId)
			return nil
		},
	}, nil
}

func fixProgName(p string) string {
	if bpf.HasProgramLargeSize() {
		return p
	}

	needsReplace := map[string]string{
		"bpf_vfs_rename.o":               "bpf_vfs_rename_v419.o",
		"bpf_filemap_fault.o":            "bpf_filemap_fault_v419.o",
		"bpf_filemap_map_pages.o":        "bpf_filemap_map_pages_v419.o",
		"bpf_filemap_page_mkwrite.o":     "bpf_filemap_page_mkwrite_v419.o",
		"bpf_security_file_permission.o": "bpf_security_file_permission_v419.o",
		"bpf_vfs_unlink.o":               "bpf_vfs_unlink_v419.o",
		"bpf_security_inode_setattr.o":   "bpf_security_inode_setattr_v419.o",
		"bpf_vfs_fallocate.o":            "bpf_vfs_fallocate_v419.o",
		"bpf_finish_open.o":              "bpf_finish_open_v419.o",
		"bpf_vfs_open.o":                 "bpf_vfs_open_v419.o",
		"bpf_security_inode_rmdir.o":     "bpf_security_inode_rmdir_v419.o",
		"bpf_vfs_mkdir.o":                "bpf_vfs_mkdir_v419.o",
		"bpf_iterate_dir.o":              "bpf_iterate_dir_v419.o",
		"bpf_security_bprm_check.o":      "bpf_security_bprm_check_v419.o",
		"bpf_security_path_rename.o":     "bpf_security_path_rename_v419.o",
		"bpf_security_inode_link.o":      "bpf_security_inode_link_v419.o",
		"bpf_security_file_open.o":       "bpf_security_file_open_v419.o",
	}

	r, ok := needsReplace[p]
	if ok {
		return r
	}
	return p
}

func getIoUringHooks(spec *btf.Spec, ioUringSupport bool, hooks []FimHook) []FimHook {
	if !ioUringSupport {
		return hooks
	}

	hasIoRead := false
	if _, err := fgsBTF.GetFuncProto(spec, "io_read", false); err == nil {
		hasIoRead = true
	}

	hasIoWrite := false
	if _, err := fgsBTF.GetFuncProto(spec, "io_write", false); err == nil {
		hasIoWrite = true
	}

	hasIoReadWrite := hasIoRead && hasIoWrite

	// first we try to load io_read and io_write hooks
	if hasIoReadWrite {
		return append(hooks, FimIoUringHooks[:]...)
	}

	logger.GetLogger().WithFields(logrus.Fields{"io_read": hasIoRead, "io_write": hasIoWrite}).Warn("Cannot find io_read/io_write hooks for io_uring. Falling back to io_issue_sqe.")

	// if they are unavailable we try to load io_issue_sqe hook
	return append(hooks, FimIoUringSingleHooks[:]...)
}

func getFileCreateHooks(spec *btf.Spec, hooks []FimHook, config *fileapi.FileConfigMapValue) []FimHook {
	vfsOpenProto, err1 := fgsBTF.GetFuncProto(spec, "vfs_open", false)
	finishOpenProto, err2 := fgsBTF.GetFuncProto(spec, "finish_open", false)
	if err1 == nil && err2 == nil && vfsOpenProto == FimHooksFileCreate[1].prog[0].proto && finishOpenProto == FimHooksFileCreate[0].prog[0].proto {
		return append(hooks, FimHooksFileCreate[:]...)
	}

	// In newer kernels (>= 4.19), we rely on (file->f_mode & FMODE_CREATED)
	// to check if a file is created.
	// Older kernels (< 4.19, i.e. 4.18 rhel8) use a different way to provide
	// the information if the file is created. This is done by using an argument
	// (int *opened) in finish_open hook. More specifically, we could use something
	// like (*opened & FILE_CREATED) to determine if a file is created. The problem
	// is that vfs_open hook does not have this argument to cover all cases.
	// Using hooks in lower functions (i.e. lookup_open) is not possible as they
	// are static and they are inlined in rhel8.
	// To support those kernels, we also hook at the fsnotify hook. We do some
	// checks to get events only for newly created file and we add the inode pair
	// (i.e. file and directory inodes) into a map (fsnotify_created_files_map).
	// Then we consume these from the normal hooks that we use for file creates.
	config.IsLessThan419 = 1
	return append(hooks, FimHooksFileCreate418[:]...)
}

func findHooks(config *fileapi.FileConfigMapValue, mode Mode, digestSupport, ioUringSupport bool) ([]FimProg, error) {
	spec, err := ossBTF.NewBTF()
	if err != nil {
		return nil, fmt.Errorf("GetCachedBTF error: %s", err)
	}
	if spec == nil {
		return nil, fmt.Errorf("GetCachedBTF returns nil")
	}

	var hooks []FimHook
	m := ""
	switch mode {
	case PathBased:
		if eeOption.Config.EnableFimDispatcher {
			hooks = FimPathBasedTailCallHooks[:]
			m = "path-based-with-dispatcher"
			if digestSupport {
				return nil, fmt.Errorf("exec digests are not supported yet with FIM dispatcher")
			}
			hooks = append(hooks, FimPathBasedTailCallHooksExec)
		} else {
			hooks = FimPathBasedHooks[:]
			// first try to attach to getname if this is not available we will try getname_flags
			// we need that because in latest kernels the getname function is inlined
			if _, err := fgsBTF.GetFuncProto(spec, "getname", false); err == nil {
				hooks = append(hooks, FimPathBasedGetnameHook)
			} else {
				hooks = append(hooks, FimPathBasedGetnameFlagsHook)
			}
			hooks = append(hooks, FimPathBasedArchHooks[:]...)
			m = "path-based"
			if digestSupport {
				for _, h := range FimPathBasedHooksExecDigests {
					hooks = append(hooks, h)
				}
				m += " with exec digests"
			} else {
				hooks = append(hooks, FimPathBasedHooksExec)
			}
		}
		hooks = getIoUringHooks(spec, ioUringSupport, hooks)
	case Observe:
		hooks = FimHooksObserve[:]
		hooks = getFileCreateHooks(spec, hooks, config)
		m = "observe"
		if digestSupport {
			for _, h := range FimHooksLsmExecDigests {
				hooks = append(hooks, h)
			}
			m += " with exec digests"
		} else {
			hooks = append(hooks, FimHooksObserveExec)
		}
		hooks = getIoUringHooks(spec, ioUringSupport, hooks)
	case EnforceFmodRet:
		hooks = FimHooksFmodRet[:]
		hooks = getFileCreateHooks(spec, hooks, config)
		m = "enforce with fmod_ret"
		if digestSupport {
			for _, h := range FimHooksLsmExecDigests {
				hooks = append(hooks, h)
			}
			m += " with exec digests"
		} else {
			hooks = append(hooks, FimHooksFmodRetExec)
		}
		hooks = getIoUringHooks(spec, ioUringSupport, hooks)
	case EnforceLSM:
		hooks = FimHooksLsm[:]
		hooks = getFileCreateHooks(spec, hooks, config)
		m = "enforce with lsm"
		if digestSupport {
			for _, h := range FimHooksLsmExecDigests {
				hooks = append(hooks, h)
			}
			m += " with exec digests"
		} else {
			hooks = append(hooks, FimHooksLsmExec)
		}
		hooks = getIoUringHooks(spec, ioUringSupport, hooks)
	default:
		return nil, fmt.Errorf("unknown mode in findHooks [%d]", mode)
	}
	logger.GetLogger().Infof("Loading file hooks for %s", m)

	fimProgs := make([]FimProg, 0)
	for _, h := range hooks {
		// In GKE 5.15 kernels io_read and io_write functions seems to be inlined.
		// On the other hand, io_issue_sqe seems to be available. We can find
		// that in /proc/kallsyms but not in the BTF. For this reason, we skip the
		// BTF check here and we try to load hooks in io_issue_sqe. If this fails
		// to attach that hook, fim will fail to load. The prototype of io_issue_sqe
		// seems to be stable along all kernels that have this function.
		if h.name == "io_issue_sqe" {
			// generate the maps
			maps := []MapInfo{}
			for _, m := range h.prog[0].maps {
				maps = append(maps, m...)
			}

			fimProgs = append(fimProgs, FimProg{h.tp, h.name, h.prog[0].progName, h.prog[0].progSection, maps})
			continue
		}

		if h.name == "tail_call" {
			// generate the maps
			maps := []MapInfo{}
			for _, m := range h.prog[0].maps {
				maps = append(maps, m...)
			}

			fimProgs = append(fimProgs, FimProg{h.tp, h.name, h.prog[0].progName, h.prog[0].progSection, maps})
			continue
		}

		kretprobe := (h.tp == "kretprobe") || (h.tp == "fexit") || (h.tp == "fexit.s")
		p, err := fgsBTF.GetFuncProto(spec, h.name, kretprobe)
		if err != nil {
			if h.name == "security_path_rename" {
				logger.GetLogger().Warnf("failed to find %s/security_path_rename hook, will continue without it", h.tp)
				config.HasSecurityPathRename = 0
				continue
			}
			return nil, fmt.Errorf("fgsBTF.GetFuncProto failed: %w", err)
		}

		progFound := false
		for _, f := range h.prog {
			if f.proto == p {
				progFound = true

				// generate the maps
				maps := []MapInfo{}
				for _, m := range f.maps {
					maps = append(maps, m...)
				}

				fimProgs = append(fimProgs, FimProg{h.tp, h.name, fixProgName(f.progName), f.progSection, maps})
				break
			}
		}
		if !progFound {
			return nil, fmt.Errorf("function %s has different prototype in BTF (BTF: %s) compared to FIM", h.name, p)
		}
	}

	return fimProgs, nil
}

// returns the mode (i.e. Observe, Enforce etc.) and if the kernel supports file digests
func probeFileMode(s *fm.KernelSelectorState, h TpMode) (Mode, bool) {
	supportTracing := utils.SupportFmodRet()
	logger.GetLogger().Infof("probeTracingModifyReturn() = %t", supportTracing)
	logger.GetLogger().Infof("HaveProgramType(ebpf.Tracing) = %t", (features.HaveProgramType(ebpf.Tracing) == nil))

	supportLSM := utils.SupportLSM()
	supportImaFileHash := (probeImaFileHashHelper() == nil)
	logger.GetLogger().Infof("probeLSM() = %t probeImaFileHashHelper() = %t", supportLSM, supportImaFileHash)
	logger.GetLogger().Infof("HaveProgramType(ebpf.LSM) = %t", (features.HaveProgramType(ebpf.LSM) == nil))

	algo, err := probeImaEnabled()
	logger.GetLogger().WithError(err).WithField("algo", algo).Infof("probeImaEnabled()")

	supportBpfLoop := (probeBpfLoop() == nil)
	logger.GetLogger().Infof("probeBpfLoop() = %t", supportBpfLoop)

	supportBpfForEachMapElem := (probeForEachMapElem() == nil)
	logger.GetLogger().Infof("probeForEachMapElem() = %t", supportBpfForEachMapElem)

	logger.GetLogger().WithFields(logrus.Fields{
		"security_file_permission":  (probeDpathSecurityFilePermission() == nil),
		"security_path_truncate":    (probeDpathSecurityPathTruncate() == nil),
		"security_file_open":        (probeDpathSecurityFileOpen() == nil),
		"security_kernel_read_file": (probeDpathSecurityKernelReadFile() == nil),
	}).Infof("probe bpf_d_path support")

	digestSupport := supportLSM && supportImaFileHash

	if h == PathBasedTpMode {
		if supportTracing && supportLSM && supportBpfLoop && supportBpfForEachMapElem {
			return PathBased, digestSupport
		}
		return PathBasedNotSupported, digestSupport
	}

	if !s.NeedEnforcement() {
		return Observe, digestSupport
	}

	// If we have support for lsm and fmod_ret we prefer to use lsm.
	if supportLSM {
		return EnforceLSM, digestSupport
	} else if supportTracing {
		return EnforceFmodRet, digestSupport
	}
	return EnforceNotSupported, digestSupport
}

type configFileSensorOptions struct {
	forceLoad                     bool
	enableExecDigests             bool
	watchedInodeMapSizePolicy     string
	watchedInodeMapMaxiumSize     uint32
	watchedInodeMapSizeMultiplier float32
	watchedInodeMapSizeConstant   uint32
}

func configFileSensorOptionsInit(opts map[string]string) (*configFileSensorOptions, error) {
	conf := configFileSensorOptions{
		forceLoad:                     false,
		enableExecDigests:             false,
		watchedInodeMapSizePolicy:     "fixed",
		watchedInodeMapMaxiumSize:     256 * 1024, // 256K
		watchedInodeMapSizeMultiplier: 4.0,
		watchedInodeMapSizeConstant:   256 * 1024, // 256K
	}

	if val, ok := opts["forceLoad"]; ok {
		boolValue, err := strconv.ParseBool(val)
		if err != nil {
			return nil, fmt.Errorf("FileMonitoring the value of spec.file.file_config.forceLoad should be a boolean. User input: [%s]", val)
		}
		conf.forceLoad = boolValue
	}

	if val, ok := opts["enableExecDigests"]; ok {
		boolValue, err := strconv.ParseBool(val)
		if err != nil {
			return nil, fmt.Errorf("FileMonitoring the value of spec.file.file_config.enableExecDigests should be a boolean. User input: [%s]", val)
		}
		conf.enableExecDigests = boolValue
	}

	if val, ok := opts["watchedInodeMapMaxiumSize"]; ok {
		v, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("FileMonitoring the value of spec.file.file_config.watchedInodeMapMaxiumSize should be a number. User input: [%s]", val)
		}
		conf.watchedInodeMapMaxiumSize = uint32(v)
	}

	if val, ok := opts["watchedInodeMapSizePolicy"]; ok {
		if val != "fixed" && val != "auto" {
			return nil, fmt.Errorf("FileMonitoring the value of spec.file.file_config.watchedInodeMapSizePolicy should be fixed or dynamic. User input: [%s]", val)
		}
		conf.watchedInodeMapSizePolicy = val
	}

	if val, ok := opts["watchedInodeMapSizeMultiplier"]; ok {
		v, err := strconv.ParseFloat(val, 32)
		if err != nil {
			return nil, fmt.Errorf("FileMonitoring the value of spec.file.file_config.watchedInodeMapSizeMultiplier should be a float. User input: [%s]", val)
		}
		conf.watchedInodeMapSizeMultiplier = float32(v)
	}

	if val, ok := opts["watchedInodeMapSizeConstant"]; ok {
		v, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("FileMonitoring the value of spec.file.file_config.watchedInodeMapSizeConstant should be a number. User input: [%s]", val)
		}
		conf.watchedInodeMapSizeConstant = uint32(v)
	}

	return &conf, nil
}

func GetTpMode(s *v1alpha1.FileSpec) (TpMode, PathBasedMatcher, error) {
	modeNum := TpMode(0)
	pathMatcher := InvalidMatcher
	for _, p := range s.PathsPatterns {
		switch tp := p.Type; tp {
		case "FilePrefixSuffix":
			modeNum |= InodeBasedTpMode
		case "PathPrefix":
			modeNum |= InodeBasedTpMode
		case "FileExactMatch":
			modeNum |= InodeBasedTpMode
		case "FileSystemType":
			modeNum |= PathBasedTpMode
			if pathMatcher != InvalidMatcher {
				return 0, InvalidMatcher, fmt.Errorf("FileSystemType cannot be combined with other path-based modes")
			}
			pathMatcher = FsTypeMatcher
		case "AllFileOps":
			modeNum |= PathBasedTpMode
			if pathMatcher != InvalidMatcher {
				return 0, InvalidMatcher, fmt.Errorf("AllFileOps cannot be combined with other path-based modes")
			}
			pathMatcher = MatchAll
		default:
			return 0, InvalidMatcher, fmt.Errorf("getHooksType unknown pattern type: %s", p.Type)
		}
	}
	return modeNum, pathMatcher, nil
}

var (
	baseFIMPolicy = "__base_file__"

	SecurityFilePermission = program.Builder(
		"fmod_ret_dispatcher.o",
		"security_file_permission",
		"fmod_ret/security_file_permission",
		"fmod_ret_security_file_permission",
		"file_monitoring",
	).SetPolicy(baseFIMPolicy).SetLoaderData(FimLoaderData{tp: "fmod_ret", tail: TailCallIndex{valid: true, index: 0}})

	SecurityKernelReadFile = program.Builder(
		"lsm_dispatcher_kernel_read_file.o",
		"kernel_read_file",
		"lsm/kernel_read_file",
		"lsm_kernel_read_file",
		"file_monitoring",
	).SetPolicy(baseFIMPolicy).SetLoaderData(FimLoaderData{tp: "lsm", tail: TailCallIndex{valid: true, index: 0}})

	SecurityFileOpen = program.Builder(
		"lsm_dispatcher_file_open.o",
		"file_open",
		"lsm/file_open",
		"lsm_file_open",
		"file_monitoring",
	).SetPolicy(baseFIMPolicy).SetLoaderData(FimLoaderData{tp: "lsm", tail: TailCallIndex{valid: true, index: 0}})

	SecurityMmapFile = program.Builder(
		"lsm_dispatcher_mmap_file.o",
		"mmap_file",
		"lsm/mmap_file",
		"lsm_mmap_file",
		"file_monitoring",
	).SetPolicy(baseFIMPolicy).SetLoaderData(FimLoaderData{tp: "lsm", tail: TailCallIndex{valid: true, index: 0}})

	SecurityPathLink = program.Builder(
		"lsm_dispatcher_path_link.o",
		"path_link",
		"lsm/path_link",
		"lsm_path_link",
		"file_monitoring",
	).SetPolicy(baseFIMPolicy).SetLoaderData(FimLoaderData{tp: "lsm", tail: TailCallIndex{valid: true, index: 0}})

	SecurityPathMkdir = program.Builder(
		"lsm_dispatcher_path_mkdir.o",
		"path_mkdir",
		"lsm/path_mkdir",
		"lsm_path_mkdir",
		"file_monitoring",
	).SetPolicy(baseFIMPolicy).SetLoaderData(FimLoaderData{tp: "lsm", tail: TailCallIndex{valid: true, index: 0}})

	SecurityPathRmdir = program.Builder(
		"lsm_dispatcher_path_rmdir.o",
		"path_rmdir",
		"lsm/path_rmdir",
		"lsm_path_rmdir",
		"file_monitoring",
	).SetPolicy(baseFIMPolicy).SetLoaderData(FimLoaderData{tp: "lsm", tail: TailCallIndex{valid: true, index: 0}})

	SecurityPathUnlink = program.Builder(
		"lsm_dispatcher_path_unlink.o",
		"path_unlink",
		"lsm/path_unlink",
		"lsm_path_unlink",
		"file_monitoring",
	).SetPolicy(baseFIMPolicy).SetLoaderData(FimLoaderData{tp: "lsm", tail: TailCallIndex{valid: true, index: 0}})

	SecurityPathTruncate = program.Builder(
		"lsm_dispatcher_path_truncate.o",
		"path_truncate",
		"lsm/path_truncate",
		"lsm_path_truncate",
		"file_monitoring",
	).SetPolicy(baseFIMPolicy).SetLoaderData(FimLoaderData{tp: "lsm", tail: TailCallIndex{valid: true, index: 0}})

	SecurityPathChmod = program.Builder(
		"lsm_dispatcher_path_chmod.o",
		"path_chmod",
		"lsm/path_chmod",
		"lsm_path_chmod",
		"file_monitoring",
	).SetPolicy(baseFIMPolicy).SetLoaderData(FimLoaderData{tp: "lsm", tail: TailCallIndex{valid: true, index: 0}})

	SecurityPathChown = program.Builder(
		"lsm_dispatcher_path_chown.o",
		"path_chown",
		"lsm/path_chown",
		"lsm_path_chown",
		"file_monitoring",
	).SetPolicy(baseFIMPolicy).SetLoaderData(FimLoaderData{tp: "lsm", tail: TailCallIndex{valid: true, index: 0}})

	SecurityPathRename = program.Builder(
		"lsm_dispatcher_path_rename.o",
		"path_rename",
		"lsm/path_rename",
		"lsm_path_rename",
		"file_monitoring",
	).SetPolicy(baseFIMPolicy).SetLoaderData(FimLoaderData{tp: "lsm", tail: TailCallIndex{valid: true, index: 0}})

	SecurityBprmCheck = program.Builder(
		"lsm_dispatcher_bprm_check_security.o",
		"bprm_check_security",
		"lsm/bprm_check_security",
		"lsm_bprm_check_security",
		"file_monitoring",
	).SetPolicy(baseFIMPolicy).SetLoaderData(FimLoaderData{tp: "lsm", tail: TailCallIndex{valid: true, index: 0}})

	SecurityPathSymlink = program.Builder(
		"lsm_dispatcher_path_symlink.o",
		"path_symlink",
		"lsm/path_symlink",
		"lsm_path_symlink",
		"file_monitoring",
	).SetPolicy(baseFIMPolicy).SetLoaderData(FimLoaderData{tp: "lsm", tail: TailCallIndex{valid: true, index: 0}})

	baseFIMPrograms = []*program.Program{
		SecurityFilePermission,
		SecurityKernelReadFile,
		SecurityFileOpen,
		SecurityMmapFile,
		SecurityPathLink,
		SecurityPathMkdir,
		SecurityPathRmdir,
		SecurityPathUnlink,
		SecurityPathTruncate,
		SecurityPathChmod,
		SecurityPathChown,
		SecurityPathRename,
		SecurityBprmCheck,
		SecurityPathSymlink,
	}

	PolicyFilterReverseMaps = program.MapBuilder("policy_filter_cgroup_maps", baseFIMPrograms...)
	TgConfMap               = program.MapBuilder("tg_conf_map", baseFIMPrograms...)
	PolicyIdToTailIndexMap  = program.MapBuilderSensor("policy_id_to_tail_index", baseFIMPrograms...)
	DisCtxHeapMap           = program.MapBuilderSensor("dis_ctx_heap", baseFIMPrograms...)

	DisCallsMaps = map[string]*program.Map{
		SecurityFilePermission.Label: program.MapBuilderProgram("fim_tail_calls", SecurityFilePermission),
		SecurityKernelReadFile.Label: program.MapBuilderProgram("fim_tail_calls", SecurityKernelReadFile),
		SecurityFileOpen.Label:       program.MapBuilderProgram("fim_tail_calls", SecurityFileOpen),
		SecurityMmapFile.Label:       program.MapBuilderProgram("fim_tail_calls", SecurityMmapFile),
		SecurityPathLink.Label:       program.MapBuilderProgram("fim_tail_calls", SecurityPathLink),
		SecurityPathMkdir.Label:      program.MapBuilderProgram("fim_tail_calls", SecurityPathMkdir),
		SecurityPathRmdir.Label:      program.MapBuilderProgram("fim_tail_calls", SecurityPathRmdir),
		SecurityPathUnlink.Label:     program.MapBuilderProgram("fim_tail_calls", SecurityPathUnlink),
		SecurityPathTruncate.Label:   program.MapBuilderProgram("fim_tail_calls", SecurityPathTruncate),
		SecurityPathChmod.Label:      program.MapBuilderProgram("fim_tail_calls", SecurityPathChmod),
		SecurityPathChown.Label:      program.MapBuilderProgram("fim_tail_calls", SecurityPathChown),
		SecurityPathRename.Label:     program.MapBuilderProgram("fim_tail_calls", SecurityPathRename),
		SecurityBprmCheck.Label:      program.MapBuilderProgram("fim_tail_calls", SecurityBprmCheck),
		SecurityPathSymlink.Label:    program.MapBuilderProgram("fim_tail_calls", SecurityPathSymlink),
	}
)

func LoadFIMInitialSensor(ctx context.Context) error {
	if eeOption.Config.EnableFimDispatcher && !option.Config.EnablePolicyFilterCgroupMap {
		return fmt.Errorf("enabling FIM dispatcher requires enabling policy filter cgroup map as well")
	}
	if !eeOption.Config.EnableFimDispatcher {
		logger.GetLogger().Info("FIM dispatcher is not enabled")
		return nil
	}
	mgr := observer.GetSensorManager()
	initialFIMSensor := &sensors.Sensor{
		Name:  baseFIMPolicy,
		Progs: baseFIMPrograms,
		Maps: []*program.Map{
			PolicyFilterReverseMaps,
			TgConfMap,
			PolicyIdToTailIndexMap,
			DisCtxHeapMap,
		},
	}
	for _, v := range DisCallsMaps {
		initialFIMSensor.Maps = append(initialFIMSensor.Maps, v)
	}
	if err := mgr.AddSensor(ctx, initialFIMSensor.Name, initialFIMSensor); err != nil {
		return err
	}
	return mgr.EnableSensor(ctx, initialFIMSensor.Name)
}

func (k *observerFileSensor) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	fid policyfilter.PolicyID,
) (sensors.SensorIface, error) {
	spec := policy.TpSpec()

	newFileSpec := spec.FileMonitoring.DeepCopy()
	for _, p := range spec.FileMonitoring.Paths {
		newFileSpec.PathsPatterns = append(newFileSpec.PathsPatterns, v1alpha1.FilePathPattern{
			Type: "PathPrefix",
			PathPrefix: &v1alpha1.PathPrefixPattern{
				Prefix: p,
			},
		})
	}
	newFileSpec.Paths = nil

	if len(spec.FileMonitoring.Paths) == 0 && len(spec.FileMonitoring.PathsPatterns) == 0 {
		return nil, nil
	}

	if len(spec.FileMonitoring.Paths) > 0 && len(spec.FileMonitoring.PathsPatterns) > 0 {
		return nil, fmt.Errorf("FileMonitoring requires only one of file_paths or file_paths_patterns to be defined")
	}

	tpConf, err := configFileSensorOptionsInit(spec.FileMonitoring.Config)
	if err != nil {
		return nil, fmt.Errorf("FileMonitoring failed to parse config: %w", err)
	}

	if !tpConf.forceLoad && !kernels.MinKernelVersion("4.18.0") {
		return nil, fmt.Errorf("FileMonitoring requires at least 4.18.0 version")
	}
	logger.GetLogger().Infof("FileMonitoring is enabled with %d prefixes and %d patterns to watch and %d exclude paths!", len(spec.FileMonitoring.Paths), len(spec.FileMonitoring.PathsPatterns), len(spec.FileMonitoring.PathsExclude))

	if !spec.FileMonitoring.MonitorHostFiles && spec.FileMonitoring.PodSelector == nil {
		logger.GetLogger().Warnf("FileMonitoring policy with false monitorHostFile and nil PodSelector will not match anything")
	}

	mode, pathMatcher, err := GetTpMode(newFileSpec)
	if err != nil {
		return nil, fmt.Errorf("FileMonitoring failed to get mode type: %w", err)
	}
	if mode == MixedTpMode {
		return nil, fmt.Errorf("FileMonitoring does not support mixes mode")
	}

	maxSel := fm.MaxFimSelectors
	if mode == PathBasedTpMode {
		maxSel = fm.MaxFimGlobSelectors
	}
	selState, err := fm.InitKernelSelectorState(spec.FileMonitoring.Selectors, maxSel)
	if err != nil {
		return nil, fmt.Errorf("FileMonitoring failed to parse selectors: %w", err)
	}

	// start tetragon-fs-scanner if it hasn't started yet
	if _, serr := os.Stat(fm.ScannerFifoPath); fsScannerCmd == nil || errors.Is(serr, os.ErrNotExist) {
		var err error
		fsScannerCmd, err = startFsScanner()
		if err != nil {
			return nil, fmt.Errorf("FileMonitoring failed to start tetragon-fs-scanner: %w", err)
		}
	}

	ioUringSupport := fm.SupportIoUring()
	logger.GetLogger().Infof("FileMonitoring kernel supports io_uring: %t", ioUringSupport)

	config := fileapi.FileConfigMapValue{
		HasSecurityPathRename: 1,
		PolicyId:              uint32(fid),
	}
	fileMode, digestSupport := probeFileMode(selState, mode)
	if !tpConf.enableExecDigests { // we explicitly disable digests if the user has not enabled them
		digestSupport = false
	}
	if tpConf.enableExecDigests && !digestSupport { // the user enables exec digests but the kernel does not support them
		logger.GetLogger().Warn("FileMonitoring: User enables file digests but the kernel does not support them. Falling back to not using them.")
	}
	progs, err := findHooks(&config, fileMode, digestSupport, ioUringSupport)
	if err != nil {
		return nil, fmt.Errorf("FileMonitoring fails to find the appropriate hooks: %w", err)
	}
	return addFileMonitoringSensor(policy, *newFileSpec, progs, config, selState, tpConf, pathMatcher, mode)
}

func setTailCallIfNeeded(args sensors.LoadProbeArgs, v FimLoaderData) error {
	if !v.tail.valid {
		return nil
	}

	// open the map with tail calls
	tailPinPath := path.Join(args.BPFDir, args.Load.PinPath, "fim_tail_calls")
	tailCallsMap, err := ebpf.LoadPinnedMap(tailPinPath, nil)
	if err != nil {
		return fmt.Errorf("loadProbe: ebpf.LoadPinnedMap fails for %s", tailPinPath)
	}
	defer tailCallsMap.Close()

	// add a new entry into tail calls map
	err = tailCallsMap.Update(uint32(v.tail.index), uint32(args.Load.Prog.FD()), 0)
	if err != nil {
		return fmt.Errorf("loadProbe: tailCallsMap.Update fails for index %d and prog %s map %s: %v", v.tail.index, args.Load.Prog, tailCallsMap, err)
	}

	return nil
}

func loadProbe(args sensors.LoadProbeArgs) error {
	v, ok := args.Load.LoaderData.(FimLoaderData)
	if !ok {
		return fmt.Errorf("type of LoaderData does not match FimLoaderData")
	}

	var err error
	switch v.tp {
	case "kprobe", "kretprobe":
		err = program.LoadKprobeProgram(args.BPFDir, args.Load, args.Maps, args.Verbose)
		if err == nil {
			err = setTailCallIfNeeded(args, v)
		}
	case "fentry", "fexit", "fmod_ret", "fentry.s", "fexit.s", "fmod_ret.s":
		err = program.LoadTracingProgram(args.BPFDir, args.Load, args.Maps, args.Verbose)
		if err == nil {
			err = setTailCallIfNeeded(args, v)
		}
	case "lsm", "lsm.s":
		err = program.LoadLSMProgramSimple(args.BPFDir, args.Load, args.Maps, args.Verbose)
		if err == nil {
			err = setTailCallIfNeeded(args, v)
		}
	case "tail_call":
		err = program.LoadProgram(args.BPFDir, args.Load, args.Maps, program.NoAttach(), args.Verbose)
		if err != nil {
			return err
		}

		// open the map with tail calls
		var tailCallsMap *ebpf.Map
		tailPinPath := path.Join(args.BPFDir, baseFIMPolicy, v.progBpfDir, "fim_tail_calls")
		tailCallsMap, err = ebpf.LoadPinnedMap(tailPinPath, nil)
		if err != nil {
			return fmt.Errorf("loadProbe: ebpf.LoadPinnedMap fails for %s", tailPinPath)
		}
		defer tailCallsMap.Close()

		// add a new entry into tail calls map
		err = tailCallsMap.Update(uint32(v.tailId), uint32(args.Load.Prog.FD()), 0)
		if err != nil {
			return fmt.Errorf("loadProbe: tailCallsMap.Update fails for index %d and prog %s map %s: %v", v.tailId, args.Load.Prog, tailCallsMap, err)
		}
	default:
		err = fmt.Errorf("file: %s programs are not supported", v.tp)
	}

	return err
}

// LoadProbe() (called when the eBPF programs are actually loaded)
func (k observerFileSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return loadProbe(args)
}
