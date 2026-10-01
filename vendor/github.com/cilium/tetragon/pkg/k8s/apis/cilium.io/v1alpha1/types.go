// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package v1alpha1

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ciliumio "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
)

const (
	// Tracing Policy (TP)

	// TPPluralName is the plural name of Cilium Tracing Policy
	TPPluralName = "tracingpolicies"

	// TPKindDefinition is the kind name of Cilium Tracing Policy
	TPKindDefinition = "TracingPolicy"

	// TPName is the full name of Cilium Egress NAT Policy
	TPName = TPPluralName + "." + ciliumio.GroupName

	// TPNamespacedPluralName is the plural name of Cilium Tracing Policy
	TPNamespacedPluralName = "tracingpoliciesnamespaced"

	// TPNamespacedName
	TPNamespacedName = TPNamespacedPluralName + "." + ciliumio.GroupName

	// TPKindDefinition is the kind name of Cilium Tracing Policy
	TPNamespacedKindDefinition = "TracingPolicyNamespaced"

	K8sDomain = "k8s"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={tetragon},singular="tracingpolicynamespaced",path="tracingpoliciesnamespaced",scope="Namespaced",shortName={tgtpn}
type TracingPolicyNamespaced struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// Tracing policy specification.
	Spec TracingPolicySpec `json:"spec"`
}

func (tp *TracingPolicyNamespaced) TpSpec() *TracingPolicySpec {
	return &tp.Spec
}

func (tp *TracingPolicyNamespaced) TpInfo() string {
	return fmt.Sprintf("%s (object:%d/%s) (type:%s/%s)", tp.ObjectMeta.Name, tp.ObjectMeta.Generation, tp.ObjectMeta.UID, tp.TypeMeta.Kind, tp.TypeMeta.APIVersion)
}

func (tp *TracingPolicyNamespaced) TpName() string {
	return tp.ObjectMeta.Name
}

func (tp *TracingPolicyNamespaced) TpNamespace() string {
	return tp.ObjectMeta.Namespace
}

func (tp *TracingPolicyNamespaced) TpDomain() string {
	return K8sDomain
}

// +genclient
// +genclient:noStatus
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={tetragon},singular="tracingpolicy",path="tracingpolicies",scope="Cluster",shortName={tgtp}
type TracingPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// Tracing policy specification.
	Spec TracingPolicySpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TracingPolicyNamespacedList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []TracingPolicyNamespaced `json:"items,omitempty"`
}

type TracingPolicySpec struct {
	// +kubebuilder:validation:Optional
	// A list of kprobe specs.
	KProbes []KProbeSpec `json:"kprobes,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of tracepoint specs.
	Tracepoints []TracepointSpec `json:"tracepoints,omitempty"`
	// +kubebuilder:validation:Optional
	// Parser policy specification.
	Parser ParserPolicySpec `json:"parser"`
	// +kubebuilder:validation:Optional
	// File monitoring policy specification.
	FileMonitoring FileSpec `json:"file"`
	// +kubebuilder:validation:Optional
	// Enable loader events
	Loader bool `json:"loader"`
	// +kubebuilder:validation:Optional
	// A list of uprobe specs.
	UProbes []UProbeSpec `json:"uprobes,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of uprobe specs.
	LsmHooks []LsmHookSpec `json:"lsmhooks,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of usdt specs.
	Usdts []UsdtSpec `json:"usdts,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of fentry specs.
	Fentries []KProbeSpec `json:"fentries,omitempty"`
	// +kubebuilder:validation:Optional
	// Hot-patch already loaded JVM classes through the local HotSpot Attach interface.
	Java *JavaPolicySpec `json:"java,omitempty"`

	// +kubebuilder:validation:Optional
	// PodSelector selects pods that this policy applies to
	PodSelector *slimv1.LabelSelector `json:"podSelector,omitempty"`

	// +kubebuilder:validation:Optional
	// ContainerSelector selects containers that this policy applies to.
	// A map of container fields will be constructed in the same way as a map of labels.
	// The name of the field represents the label "key", and the value of the field - label "value".
	// Currently, only the "name" field is supported.
	ContainerSelector *slimv1.LabelSelector `json:"containerSelector,omitempty"`

	// +kubebuilder:validation:Optional
	// HostSelector selects hosts that this policy applies to.
	// For now only ~ (none) and {} (all) is supported.
	HostSelector *slimv1.LabelSelector `json:"hostSelector,omitempty"`

	// +kubebuilder:validation:Optional
	// NodeSelector selects the nodes, by label, on which Tetragon agents load
	// this policy. If empty or unset, the policy is loaded on all nodes. This differs in
	// purpose from hostSelector: nodeSelector controls where a policy is loaded
	// (on which nodes), whereas hostSelector controls which workloads a loaded
	// policy applies to (host vs pod workloads) and does not affect whether the
	// policy is loaded on a node. Use nodeSelector to target a node group such
	// as GPU nodes, a specific architecture or OS, or a canary pool; use
	// hostSelector to scope a loaded policy to host workloads. Unlike
	// hostSelector, nodeSelector supports arbitrary matchLabels and
	// matchExpressions.
	NodeSelector *slimv1.LabelSelector `json:"nodeSelector,omitempty"`

	// +kubebuilder:validation:Optional
	// A list of list specs.
	Lists []ListSpec `json:"lists,omitempty"`

	// +kubebuilder:validation:Optional
	// A enforcer spec.
	Enforcers []EnforcerSpec `json:"enforcers,omitempty"`

	// +kubebuilder:validation:Optional
	// A list of overloaded options
	Options []OptionSpec `json:"options,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Optional
	// SelectorsMacros is used to define selectors macros, which can be used
	// in probes/hooks selectors by their names.
	SelectorsMacros map[string]KProbeSelector `json:"selectorsMacros,omitempty"`
}

// JavaPolicySpec defines class redefinitions sent through HotSpot Attach.
type JavaPolicySpec struct {
	// Exact executable paths of Java processes eligible for attachment.
	// +kubebuilder:validation:MinItems=1
	Executables []string `json:"executables"`
	// Every token must occur in the NUL-separated process argument vector.
	ProcessArgsContains []string `json:"processArgsContains,omitempty"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	Patches []JavaClassPatch `json:"patches"`
}

// JavaClassPatch contains complete JVM class files before and after the fix.
type JavaClassPatch struct {
	Signature   string `json:"signature"`
	Replacement []byte `json:"replacement"`
	Rollback    []byte `json:"rollback"`
}

func (tp *TracingPolicy) TpSpec() *TracingPolicySpec {
	return &tp.Spec
}

func (tp *TracingPolicy) TpInfo() string {
	return fmt.Sprintf("%s (object:%d/%s) (type:%s/%s)", tp.ObjectMeta.Name, tp.ObjectMeta.Generation, tp.ObjectMeta.UID, tp.TypeMeta.Kind, tp.TypeMeta.APIVersion)
}

func (tp *TracingPolicy) TpName() string {
	return tp.ObjectMeta.Name
}

func (tp *TracingPolicy) TpNamespace() string {
	return ""
}

func (tp *TracingPolicy) TpDomain() string {
	return K8sDomain
}

// OperationSelectorValue represents the value for MatchOperations.
//
// +kubebuilder:validation:Enum=FILE_INVALID;FILE_WRITE;FILE_READ;FILE_DELETE;FILE_CREATE;FILE_RMDIR;FILE_MKDIR;FILE_RENAME;FILE_READDIR;FILE_CHATTR;FILE_EXEC;FILE_LINK;FILE_OPEN;FILE_SYMLINK;FILE_OPENRAW;FILE_UNIX_SOCKET_CONNECT;FILE_UNIX_SOCKET_CREATE;FILE_UNIX_SOCKET_DELETE
type OperationSelectorValue = string

type OperationSelector struct {
	// +kubebuilder:validation:Enum=In;NotIn
	// Filter operation.
	Operator string `json:"operator"`
	// Value to compare the argument against.
	Values []OperationSelectorValue `json:"values,omitempty"`
}

type FileActionSelector struct {
	// +kubebuilder:validation:Enum=Post;Block;NoPost
	// Action to Execute. Post will post an event; Block will also post an event, and additionally block the operation (application will receive an error).
	Action string `json:"action"`
	// +kubebuilder:validation:Optional
	// A short message of 256 characters max that will be included in the event output to inform users which selector is matched.
	Message string `json:"message"`
}

// Example: "sha1:f2e2c1b280ae3268c15fd31cd8d2fcec9a984c5f"
type DigestSelectorValue = string

type DigestSelector struct {
	// +kubebuilder:validation:Enum=In;NotIn
	// Filter operation.
	Operator string `json:"operator"`
	// Value to compare the argument against.
	Values []DigestSelectorValue `json:"values,omitempty"`
}

// +kubebuilder:validation:Enum=File;Directory
type RenameTypeSelectorValue = string

type FileRenameTypeSelector struct {
	// +kubebuilder:validation:Enum=In
	// Filter operation.
	Operator string `json:"operator"`
	// Value to compare the argument against.
	Values []RenameTypeSelectorValue `json:"values,omitempty"`
}

// +kubebuilder:validation:Enum=O_APPEND;O_ASYNC;O_CLOEXEC;O_CREAT;O_DIRECT;O_DIRECTORY;O_DSYNC;O_EXCL;O_NOATIME;O_NOCTTY;O_NOFOLLOW;O_NONBLOCK;O_PATH;O_SYNC;O_TMPFILE;O_TRUNC;O_RDONLY;O_RDWR;O_WRONLY
type OpenFlagSelectorValue = string

type FileOpenFlagsTypeSelector struct {
	// +kubebuilder:validation:Enum=In;NotIn
	// Filter operation.
	Operator string `json:"operator"`
	// Value to compare the argument against.
	Values []OpenFlagSelectorValue `json:"values,omitempty"`
}

// Example: "ab*bc?d"
type GlobPattern = string

type FilePathGlobSelector struct {
	// +kubebuilder:validation:Enum=InPattern;InFileWithDigest
	// Filter operation. Possible values:
	// - InPattern: Match the filename against the glob pattern.
	// - InFileWithDigest: Match the filename against the filename and the digest.
	//                     In that case, we only support exact file match and
	//                     glob pattern is not supported.
	Operator string `json:"operator"`
	// Glob patterns (when operator is InPattern) or filenames (when operator is InFileWithDigest) to compare the argument against.
	Values []GlobPattern `json:"values,omitempty"`
}

// +kubebuilder:validation:Enum=True;False;Any
// +kubebuilder:default=Any
type ExecAttributes = string

type FileExecAttributesSelector struct {
	// Shows if the executable file of the current process is an anonymous file created using memfd_create(). Relevant to detect malicious in-memory code injection.
	IsFromMemfd ExecAttributes `json:"isFromMemFd,omitempty"`
	// Shows if this process' executable file is in upper layer in overlayfs. If true, this means that the file is added on the container after the creation of it.
	IsUpperLayer ExecAttributes `json:"isUpperLayer,omitempty"`
}

// +kubebuilder:validation:Enum=Succeed;Failed
type OpenrawResultValue = string

type FileOpenrawResultSelector struct {
	// Matches on the return value of FILE_OPENRAW operations.
	Result OpenrawResultValue `json:"result,omitempty"`
}

type UidGidValues struct {
	// +kubebuilder:validation:Enum=In;NotIn
	// Filter operation.
	Operator string `json:"operator"`
	// the values of gid/uid to match
	Values []uint32 `json:"values,omitempty"`
}

type UidGidSelector struct {
	// +kubebuilder:validation:Optional
	// Matches on uid value.
	Uid []UidGidValues `json:"uid,omitempty"`
	// +kubebuilder:validation:Optional
	// Matches on gid value.
	Gid []UidGidValues `json:"gid,omitempty"`
}

type ProcessDurationSelector struct {
	// +kubebuilder:validation:Enum=lt;LT;LessThan;gt;GT;GreaterThan
	// Filter operation.
	Operator string `json:"operator"`
	// +kubebuilder:validation:Format=duration
	// The time to compare with the process duration. Accepts unit suffix such as ns, us, ms, s, etc.
	Value string `json:"value"`
}

// +kubebuilder:validation:Enum=PRIVILEGES_RAISED_EXEC_FILE_CAP;PRIVILEGES_RAISED_EXEC_FILE_SETUID;PRIVILEGES_RAISED_EXEC_FILE_SETGID
type PrivilegesChanged = string

type PrivilegesChangedSelector struct {
	// +kubebuilder:validation:Enum=In;NotIn
	// Filter operation.
	Operator string `json:"operator"`
	// the types of privileges changed to match (ORed)
	Values []PrivilegesChanged `json:"values,omitempty"`
}

type BinaryPropertiesSelector struct {
	// +kubebuilder:validation:Optional
	// Matches on privileges_changed value.
	PrivilegesChanged []PrivilegesChangedSelector `json:"privileges_changed,omitempty"`
	// +kubebuilder:validation:Optional
	// Matches on setuid value.
	SetUid []UidGidValues `json:"setuid,omitempty"`
	// +kubebuilder:validation:Optional
	// Matches on setgid value.
	SetGid []UidGidValues `json:"setgid,omitempty"`
}

// FileSelector selects file operations.
type FileSelector struct {
	// +kubebuilder:validation:Optional
	// A list of binary exec name filters.
	MatchBinaries []BinarySelector `json:"matchBinaries,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of operation filters.
	MatchOperations []OperationSelector `json:"matchOperations,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of operation filters.
	MatchDigests []DigestSelector `json:"matchDigests,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:deprecatedversion:warning="matchLinuxNamespaces is deprecated. Use matchNamespaces instead."
	// A list of namespaces and IDs
	// Deprecated: Use matchNamespaces instead.
	MatchNamespaces []FileNamespaceSelector `json:"matchLinuxNamespaces,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of namespaces and IDs
	MatchNamespacesOSS []NamespaceSelector `json:"matchNamespaces,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:deprecatedversion:warning="matchLinuxCapabilities is deprecated. Use matchCapabilities instead."
	// A list of capabilities and IDs
	// Deprecated: Use matchCapabilities instead.
	MatchCapabilities []FileCapabilitiesSelector `json:"matchLinuxCapabilities,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of capabilities and IDs
	MatchCapabilitiesOSS []CapabilitiesSelector `json:"matchCapabilities,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of file rename type filters.
	MatchRenameSrcType []FileRenameTypeSelector `json:"matchRenameSrcType,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of file open flags filters.
	MatchOpenFlags []FileOpenFlagsTypeSelector `json:"matchOpenFlags,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of glob patterns to match the filename.
	MatchFilename []FilePathGlobSelector `json:"matchFilename,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of exec attributes to match on the event.
	MatchExecAttributes []FileExecAttributesSelector `json:"matchExecAttributes,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of results to match on openraw operations.
	MatchOpenrawResult []FileOpenrawResultSelector `json:"matchOpenrawResult,omitempty"`
	// +kubebuilder:validation:Optional
	// Match on uid and gid values.
	MatchUidGid []UidGidSelector `json:"matchUidGid,omitempty"`
	// +kubebuilder:validation:Optional
	// Match on process duration.
	MatchProcessDuration []ProcessDurationSelector `json:"matchProcessDuration,omitempty"`
	// +kubebuilder:validation:Optional
	// Match on binary_properties. Valid only in PROCESS_EXEC events.
	MatchBinaryProperties []BinaryPropertiesSelector `json:"matchBinaryProperties,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of actions to execute when this selector matches. For now we only support a single action and users can select either Post or Block. We use an array to potentially support additional actions in the future.
	MatchActions []FileActionSelector `json:"matchActions,omitempty"`
}

// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=128
// +kubebuilder:validation:Pattern=\/.*
// Required and should start with "/". Maximum length is 128 characters.
type PathPrefix = string

type FilePrefixSuffixPattern struct {
	// +kubebuilder:validation:Required
	// The prefix of the path to match.
	Prefix PathPrefix `json:"prefix,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=128
	// The suffix of the file to match. Can be empty. In that case, we only use the prefix. Maximum length is 128 characters.
	Suffix string `json:"suffix,omitempty"`
}

type PathPrefixPattern struct {
	// +kubebuilder:validation:Required
	// The prefix of the path to match.
	Prefix PathPrefix `json:"prefix,omitempty"`
}

type FileExactMatchPattern struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:Pattern=\/.*
	// The full path of a file to match.
	Path string `json:"path,omitempty"`
}

// +kubebuilder:validation:Enum=sysfs;proc;debugfs;securityfs;overlayfs;tracefs;bpffs;fuse;ext4;ext3;ext2;xfs;ramfs;tmpfs;ceph;btrfs;smb;smb2;cifs;cgroup;cgroup2;binfmt_misc;nfs;pstore;autofs;nsfs;devpts
type FileSystemName = string

type FileSystemTypePattern struct {
	Names []FileSystemName `json:"names,omitempty"`
}

// +kubebuilder:validation:Enum=link;file;dir;chardev;blkdev
type InodeTypeName = string

type InodeTypePattern struct {
	Types []InodeTypeName `json:"types,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="(self.type == 'FilePrefixSuffix' && has(self.file_prefix_suffix)) || (self.type == 'PathPrefix' && has(self.path_prefix)) || (self.type == 'FileExactMatch' && has(self.file_exact_match)) || (self.type == 'FileSystemType' && has(self.file_system_type)) || (self.type == 'AllFileOps') || (self.type == 'InodeType' && has(self.inode_type))",message="Type should match the argument type."
type FilePathPattern struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=FilePrefixSuffix;PathPrefix;FileExactMatch;FileSystemType;AllFileOps;InodeType
	// FilePrefixSuffix can be used to match only files that have a specific prefix and optionally a suffix.
	// PathPrefix can be used for all files and directories that match a specific prefix.
	// FileExactMatch can be used to match only files that have a specific name.
	// FileSystemType can be used to specify operation only on a specific type.
	// InodeType can be used to specify if we match on regular files, directories, links, block devices, or character devices.
	Type string `json:"type"`
	// +kubebuilder:validation:Optional
	// Should be defined in the case of type=FilePrefixSuffix.
	FilePrefixSuffix *FilePrefixSuffixPattern `json:"file_prefix_suffix,omitempty"`
	// +kubebuilder:validation:Optional
	// Should be defined in the case of type=PathPrefix.
	PathPrefix *PathPrefixPattern `json:"path_prefix,omitempty"`
	// +kubebuilder:validation:Optional
	// Should be defined in the case of type=FileExactMatch.
	FileExactMatch *FileExactMatchPattern `json:"file_exact_match,omitempty"`
	// +kubebuilder:validation:Optional
	// Should be defined in the case of type=FileSystemType.
	FileSystemType *FileSystemTypePattern `json:"file_system_type,omitempty"`
	// +kubebuilder:validation:Optional
	// Should be defined in the case of type=InodeType.
	InodeType *InodeTypePattern `json:"inode_type,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="(has(self.file_paths_patterns) && (size(self.file_paths_patterns.filter(c, c.type == 'FilePrefixSuffix')) <= 32)) || (!has(self.file_paths_patterns))",message="We support up to 32 entries with type FilePrefixSuffix under file_paths_patterns."
type FileSpec struct {
	// +kubebuilder:validation:Optional
	// What paths to exclude from monitored paths.
	PathsExclude []string `json:"file_paths_exclude,omitempty"`
	// +kubebuilder:validation:Optional
	// What paths to monitor using patterns.
	PathsPatterns []FilePathPattern `json:"file_paths_patterns,omitempty"`
	// +kubebuilder:validation:Optional
	// Config flags to enable/disable specific functionality
	Config map[string]string `json:"file_config,omitempty"`
	// +kubebuilder:validation:Optional
	// Selectors to apply before producing trace output. Selectors are ORed.
	Selectors []FileSelector `json:"selectors,omitempty"`
	// +kubebuilder:default=true
	// +kubebuilder:validation:Optional
	// Do monitoring on host files
	MonitorHostFiles bool `json:"monitorHostFiles"`
	// +kubebuilder:validation:Optional
	// This is a label selector which selects Pods. This field follows standard label
	// selector semantics; if present but empty, it selects all pods.
	PodSelector *slimv1.LabelSelector `json:"podSelector,omitempty"`
	// +kubebuilder:validation:optional
	// +kubebuilder:validation:MaxItems=16
	// Tags to categorize the event, will be include in the event output.
	// Maximum of 16 Tags are supported.
	Tags []string `json:"tags,omitempty"`
}

type FileCapabilitiesSelector struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=Effective;Inheritable;Permitted
	// +kubebuilder:default=Effective
	// Type of capabilities
	Type string `json:"type"`
	// +kubebuilder:validation:Enum=In;NotIn
	// Namespace selector operator.
	Operator string `json:"operator"`
	// Capabilities to match.
	Values []string `json:"values"`
}

type FileNamespaceSelector struct {
	// +kubebuilder:validation:Enum=Uts;Ipc;Mnt;Pid;PidForChildren;Net;Time;TimeForChildren;Cgroup;User
	// Namespace selector name.
	Namespace string `json:"namespace"`
	// +kubebuilder:validation:Enum=All;Host;NoHost
	// +kubebuilder:default=All
	// Namespace selector filter type.
	Filter string `json:"filter"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TracingPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []TracingPolicy `json:"items,omitempty"`
}

type TlsSelector struct {
	// +kubebuilder:validation:Optional
	// A list of ports to match. Ports are ORd.
	MatchPorts []uint32 `json:"matchPorts,omitempty"`
}

type TlsSpec struct {
	// TLS enable parser
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Enum=socket;tc;cgroup;
	// +kubebuilder:default=cgroup
	// TLS parser type
	Mode string `json:"mode,omitempty"`
	// +kubebuilder:validation:Optional
	// Selectors to apply TLS parser against. Selectors are ORed.
	Selectors []TlsSelector `json:"selectors,omitempty"`
	// +kubebuilder:validation:Optional
	// Metrics Configuration.
	// Labels enabled by default: namespace, workload, binary
	// Configurable labels: namespace, workload, pod, binary
	Metrics *PromMetrics `json:"metrics,omitempty"`
}

type HttpsSelector struct {
	// +kubebuilder:validation:Optional
	// A list of ports to match. Ports are ORd.
	MatchPorts []uint32 `json:"matchPorts,omitempty"`
}

type HttpsSpec struct {
	// HTTPS enable parser
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Selectors to apply TLS parser against. Selectors are ORed.
	Selectors []HttpsSelector `json:"selectors,omitempty"`
}

type HttpSelector struct {
	// +kubebuilder:validation:Optional
	// A list of ports to match. Ports are ORd.
	MatchPorts []uint32 `json:"matchPorts,omitempty"`
}

type HttpSpec struct {
	// Http enable parser
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Selectors to apply TLS parser against. Selectors are ORed.
	Selectors []HttpSelector `json:"selectors,omitempty"`
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	// Enable HTTP2 parser
	Http2 bool `json:"http2"`
	// +kubebuilder:validation:Optional
	// Metrics Configuration.
	// Labels enabled by default: namespace, workload, binary, dstnamespace, dstworkload, dstdns, host
	// Configurable labels: namespace, workload, pod, binary, dstnamespace, dstworkload, dstpod, dstdns, host
	Metrics *PromMetrics `json:"metrics,omitempty"`
}

type InterfacePolicySpec struct {
	// Interface enable parser
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Interface interval in seconds
	StatsInterval uint32 `json:"statsInterval"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:deprecatedversion:warning="interface packet option is deprecated."
	// Interface packet level BPF
	Packet bool `json:"packet"`
}

type DnsPolicySpec struct {
	// DNS enable parser
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// A list of DNS ports
	Ports []uint16 `json:"ports,omitempty"`
	// +kubebuilder:validation:Optional
	// Metrics Configuration.
	// Labels enabled by default: namespace, workload, binary
	// Configurable labels: namespace, workload, pod, binary
	Metrics *PromMetrics `json:"metrics,omitempty"`
	// +kubebuilder:validation:Optional
	// Whether to report DNS questions
	ReportQuestions bool `json:"reportQuestions"`
}

type NopSelector struct {
	// +kubebuilder:validation:Optional
	// A list of ports to match. Ports are ORd.
	MatchPorts []uint32 `json:"matchPorts,omitempty"`
}

type NopSpec struct {
	// Nop enable parser
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Selectors to apply Nop parser against. Selectors are ORed.
	Selectors []NopSelector `json:"selectors,omitempty"`
}

type PromMetrics struct {
	// +kubebuilder:default=true
	// +kubebuilder:validation:Optional
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// List of enabled metrics labels. It can be used to control the metrics cardinality.
	// For the lists of labels enabled by default and configurable, see the parent object.
	// Null value means the default label set.
	// Empty list disables all configurable labels.
	// Unknown labels are ignored.
	LabelFilter []string `json:"labelFilter"`
}

type ParserPolicySpec struct {
	// +kubebuilder:validation:Optional
	// A Tls specs.
	Tls TlsSpec `json:"tls"`
	// +kubebuilder:validation:Optional
	// A Tls specs.
	Https HttpsSpec `json:"https"`
	// +kubebuilder:validation:Optional
	// A Http spec.
	Http HttpSpec `json:"http"`
	// +kubebuilder:validation:Optional
	// +nullable
	// ICMP policy specification
	Icmp *IcmpPolicySpec `json:"icmp"`
	// +kubebuilder:validation:Optional
	// +nullable
	// Raw socket policy specification
	Rawsock *RawsockPolicySpec `json:"rawsock"`
	// +kubebuilder:validation:Optional
	// +nullable
	// UDP policy specification
	Udp *UdpPolicySpec `json:"udp"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	Interface InterfacePolicySpec `json:"interface"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	Dns DnsPolicySpec `json:"dns"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	Nop NopSpec `json:"nop"`
	// +kubebuilder:validation:Optional
	// +nullable
	// TCP policy specification
	Tcp *TcpPolicySpec `json:"tcp"`
	// +kubebuilder:validation:Optional
	// UDP and TCP burst exit checking policy specification
	// +kubebuilder:deprecatedversion:warning="burstExitGen is deprecated. Use networkWatermarksExitGen instead"
	BurstExitGen NetworkWatermarksExitGenPolicySpec `json:"burstExitGen"`
	// +kubebuilder:validation:Optional
	// UDP and TCP watermarks exit checking policy specification
	NetworkWatermarksExitGen NetworkWatermarksExitGenPolicySpec `json:"networkWatermarksExitGen"`
	// +kubebuilder:validation:Optional
	// UDP and TCP heartbeat policy specification
	Heartbeat HeartbeatPolicySpec `json:"heartbeat"`
}

type TcpRttHistogram struct {
	// Enable TCP RTT Histogram
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Configures the expected RTT Max value
	Max uint32 `json:"max"`
	// +kubebuilder:validation:Optional
	// Configures the expected RTT Min value
	Min uint32 `json:"min"`
}

type TcpPolicySpec struct {
	// +kubebuilder:validation:Optional
	// Enable TCP statistics
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Configures the Stat collection interval in seconds
	StatsInterval uint32 `json:"statsInterval"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	// +kubebuilder:deprecatedversion:warning="burst is deprecated. Use watermarks instead"
	Burst TcpWatermarksPolicySpec `json:"burst"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	Watermarks TcpWatermarksPolicySpec `json:"watermarks"`
	// +kubebuilder:validation:Optional
	// Rtt Histogram
	RttHistogram TcpRttHistogram `json:"histogram"`
	// +kubebuilder:validation:Optional
	// Metrics Configuration.
	// Labels enabled by default: namespace, workload, binary, dstnamespace, dstworkload, dstdns
	// Configurable labels: namespace, workload, pod, binary, dstnamespace, dstworkload, dstpod, dstdns, dstip
	Metrics *PromMetrics `json:"metrics,omitempty"`
	// +kubebuilder:validation:Optional
	// Disable TCP events
	DisableEvents TcpEventDisablePolicySpec `json:"disableEvents"`
}

type TcpWatermarksPolicySpec struct {
	// Enable TCP watermarks observability
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	Enable bool `json:"enable"`
	// +kubebuilder:default=1000
	// +kubebuilder:validation:Optional
	// Configures the watermarks window size in milliseconds
	WindowSize uint32 `json:"windowSize"`
	// +kubebuilder:default=100
	// +kubebuilder:validation:Optional
	// Configures the percent over average deemed to be a burst
	// +kubebuilder:deprecatedversion:warning="triggerPercent is deprecated. Use burstTriggerPercent instead"
	TriggerPercent uint32 `json:"triggerPercent"`
	// +kubebuilder:default=100
	// +kubebuilder:validation:Optional
	// Configures the percent over average deemed to be a burst
	BurstTriggerPercent uint32 `json:"burstTriggerPercent"`
	// +kubebuilder:default=100
	// +kubebuilder:validation:Optional
	// Configures the percent under average deemed to be a dip
	DipTriggerPercent uint32 `json:"dipTriggerPercent"`
}

type IcmpPolicySpec struct {
	// Enable ICMP observability
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	Enable bool `json:"enable"`
	// Enable ICMPv6 info message observability
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	V6Info bool `json:"v6info"`
}

type RawsockPolicySpec struct {
	// Enable raw socket observability
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	Enable bool `json:"enable"`
	// Enable raw socket close events
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	ReportClose bool `json:"reportClose"`
	// +kubebuilder:validation:Optional
	// Metrics Configuration.
	// Labels enabled by default: namespace, workload, binary
	// Configurable labels: namespace, workload, pod, binary
	Metrics *PromMetrics `json:"metrics,omitempty"`
}

type UdpPolicySpec struct {
	// +kubebuilder:validation:Optional
	// Enable UDP observability
	Enable bool `json:"enable"`
	// +kubebuilder:default=true
	// +kubebuilder:validation:Optional
	// UDP has two modes one for newer kernels (cgroup) and then an
	// older fallback mode for kprobe use cases. Allow running older
	// kprobe version on newer kernels by setting cgroup knob to false.
	Cgroup bool `json:"cgroup"`
	// +kubebuilder:validation:Optional
	// Configures the Stat collection interval in seconds
	StatsInterval uint32 `json:"statsInterval"`
	// +kubebuilder:validation:Optional
	// Configure socket idle time to delete sockets in seconds
	DeleteIdleSocketInterval uint32 `json:"deleteIdleSocketInterval"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	// kubebuilder:deprecatedversion:warning="burst is deprecated. Use watermarks instead"
	Burst UdpWatermarksPolicySpec `json:"burst"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	Watermarks UdpWatermarksPolicySpec `json:"watermarks"`
	// +kubebuilder:validation:Optional
	// Metrics Configuration.
	// Labels enabled by default: namespace, workload, binary, dstnamespace, dstworkload, dstdns, srcmcast, dstmcast
	// Configurable labels: namespace, workload, pod, binary, dstnamespace, dstworkload, dstpod, dstdns, dstip, srcmcast, dstmcast
	Metrics *PromMetrics `json:"metrics,omitempty"`
	// +kubebuilder:validation:Optional
	// Disable UDP events
	DisableEvents UdpEventDisablePolicySpec `json:"disableEvents"`
}

type UdpWatermarksPolicySpec struct {
	// Enable UDP watermarks observability
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	Enable bool `json:"enable"`
	// +kubebuilder:default=1000
	// +kubebuilder:validation:Optional
	// Configures the burst window size in milliseconds
	WindowSize uint32 `json:"windowSize"`
	// +kubebuilder:default=100
	// +kubebuilder:validation:Optional
	// Configures the percent over average deemed to be a burst
	// +kubebuilder:deprecatedversion:warning="triggerPercent is deprecated. Use burstTriggerPercent instead"
	TriggerPercent uint32 `json:"triggerPercent"`
	// +kubebuilder:default=100
	// +kubebuilder:validation:Optional
	// Configures the percent over average deemed to be a burst
	BurstTriggerPercent uint32 `json:"burstTriggerPercent"`
	// +kubebuilder:default=100
	// +kubebuilder:validation:Optional
	// Configures the percent under average deemed to be a dip
	DipTriggerPercent uint32 `json:"dipTriggerPercent"`
}

type NetworkWatermarksExitGenPolicySpec struct {
	// Enable watermarks checks for end events from userland
	// +kubebuilder:default=true
	// +kubebuilder:validation:Optional
	Enable bool `json:"enable"`
	// +kubebuilder:default=1000
	// +kubebuilder:validation:Optional
	// Configures the checking interval in milliseconds
	Interval uint32 `json:"interval"`
}

type HeartbeatPolicySpec struct {
	// Enable heartbeat
	// +kubebuilder:default=true
	// +kubebuilder:validation:Optional
	Enable bool `json:"enable"`
	// +kubebuilder:default=60
	// +kubebuilder:validation:Optional
	// Configures the heartbeat interval in seconds
	Interval uint32 `json:"interval"`
	// +kubebuilder:default=6399
	// +kubebuilder:validation:Optional
	// Configures the UDP port
	UdpPort uint32 `json:"udpPort"`
	// +kubebuilder:default=6399
	// +kubebuilder:validation:Optional
	// Configures the TCP port
	TcpPort uint32 `json:"tcpPort"`
}

type TcpEventDisablePolicySpec struct {
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	// Disable connect events
	DisableConnect bool `json:"disableConnect"`
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	// Disable close events
	DisableClose bool `json:"disableClose"`
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	// Disable accept events
	DisableAccept bool `json:"disableAccept"`
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	// Disable listen events
	DisableListen bool `json:"disableListen"`
}

type UdpEventDisablePolicySpec struct {
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	// Disable connect events
	DisableConnect bool `json:"disableConnect"`
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	// Disable listen events
	DisableListen bool `json:"disableListen"`
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	// Disable close events
	DisableClose bool `json:"disableClose"`
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	// Disable stats events, write to metrics directly
	DisableStats bool `json:"disableStats"`
}
