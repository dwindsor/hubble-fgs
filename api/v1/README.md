# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [tetragon/capabilities.proto](#tetragon/capabilities.proto)
    - [CapabilitiesType](#tetragon.CapabilitiesType)
    - [ProcessPrivilegesChanged](#tetragon.ProcessPrivilegesChanged)
    - [SecureBitsType](#tetragon.SecureBitsType)
  
- [tetragon/dns.proto](#tetragon/dns.proto)
    - [DnsInfo](#tetragon.DnsInfo)
    - [ProcessDns](#tetragon.ProcessDns)
  
    - [DnsType](#tetragon.DnsType)
  
- [tetragon/events.proto](#tetragon/events.proto)
    - [AggregationInfo](#tetragon.AggregationInfo)
    - [AggregationOptions](#tetragon.AggregationOptions)
    - [FieldFilter](#tetragon.FieldFilter)
    - [Filter](#tetragon.Filter)
    - [GetEventsRequest](#tetragon.GetEventsRequest)
    - [GetEventsResponse](#tetragon.GetEventsResponse)
    - [RateLimitInfo](#tetragon.RateLimitInfo)
  
    - [EventType](#tetragon.EventType)
    - [FieldFilterAction](#tetragon.FieldFilterAction)
  
- [tetragon/fgs.proto](#tetragon/fgs.proto)
    - [AttrArg](#tetragon.AttrArg)
    - [AttrChange](#tetragon.AttrChange)
    - [FileArgument](#tetragon.FileArgument)
    - [FileAttr](#tetragon.FileAttr)
    - [FileDetails](#tetragon.FileDetails)
    - [FileDigest](#tetragon.FileDigest)
    - [FileIO](#tetragon.FileIO)
    - [FileLocation](#tetragon.FileLocation)
    - [FileSystem](#tetragon.FileSystem)
    - [GenericFileArg](#tetragon.GenericFileArg)
    - [Histogram](#tetragon.Histogram)
    - [HistogramBucket](#tetragon.HistogramBucket)
    - [HttpHeader](#tetragon.HttpHeader)
    - [HttpInfo](#tetragon.HttpInfo)
    - [HttpRequest](#tetragon.HttpRequest)
    - [HttpResponse](#tetragon.HttpResponse)
    - [Inode](#tetragon.Inode)
    - [InterfaceStats](#tetragon.InterfaceStats)
    - [ProcessAccept](#tetragon.ProcessAccept)
    - [ProcessClose](#tetragon.ProcessClose)
    - [ProcessConnect](#tetragon.ProcessConnect)
    - [ProcessFile](#tetragon.ProcessFile)
    - [ProcessFileExec](#tetragon.ProcessFileExec)
    - [ProcessHttp](#tetragon.ProcessHttp)
    - [ProcessIcmp](#tetragon.ProcessIcmp)
    - [ProcessIpError](#tetragon.ProcessIpError)
    - [ProcessListen](#tetragon.ProcessListen)
    - [ProcessNetworkBurst](#tetragon.ProcessNetworkBurst)
    - [ProcessNetworkWatermark](#tetragon.ProcessNetworkWatermark)
    - [ProcessRawsockClose](#tetragon.ProcessRawsockClose)
    - [ProcessRawsockCreate](#tetragon.ProcessRawsockCreate)
    - [ProcessSockStats](#tetragon.ProcessSockStats)
    - [ProcessUdpSeqCheckError](#tetragon.ProcessUdpSeqCheckError)
    - [ReadDirArg](#tetragon.ReadDirArg)
    - [RenameFileArg](#tetragon.RenameFileArg)
    - [SockInfo](#tetragon.SockInfo)
    - [SocketStats](#tetragon.SocketStats)
    - [Tls](#tetragon.Tls)
  
    - [DigestAlgo](#tetragon.DigestAlgo)
    - [FileAction](#tetragon.FileAction)
    - [FileOperation](#tetragon.FileOperation)
    - [FileScope](#tetragon.FileScope)
    - [SocketProtocol](#tetragon.SocketProtocol)
    - [TlsCertificateError](#tetragon.TlsCertificateError)
  
- [tetragon/sandbox.proto](#tetragon/sandbox.proto)
    - [ProcessSandboxSyscall](#tetragon.ProcessSandboxSyscall)
  
- [tetragon/sensors.proto](#tetragon/sensors.proto)
    - [AddTracingPolicyRequest](#tetragon.AddTracingPolicyRequest)
    - [AddTracingPolicyResponse](#tetragon.AddTracingPolicyResponse)
    - [DeleteTracingPolicyRequest](#tetragon.DeleteTracingPolicyRequest)
    - [DeleteTracingPolicyResponse](#tetragon.DeleteTracingPolicyResponse)
    - [DisableSensorRequest](#tetragon.DisableSensorRequest)
    - [DisableSensorResponse](#tetragon.DisableSensorResponse)
    - [DisableTracingPolicyRequest](#tetragon.DisableTracingPolicyRequest)
    - [DisableTracingPolicyResponse](#tetragon.DisableTracingPolicyResponse)
    - [EnableSensorRequest](#tetragon.EnableSensorRequest)
    - [EnableSensorResponse](#tetragon.EnableSensorResponse)
    - [EnableTracingPolicyRequest](#tetragon.EnableTracingPolicyRequest)
    - [EnableTracingPolicyResponse](#tetragon.EnableTracingPolicyResponse)
    - [GetStackTraceTreeRequest](#tetragon.GetStackTraceTreeRequest)
    - [GetStackTraceTreeResponse](#tetragon.GetStackTraceTreeResponse)
    - [GetVersionRequest](#tetragon.GetVersionRequest)
    - [GetVersionResponse](#tetragon.GetVersionResponse)
    - [ListSensorsRequest](#tetragon.ListSensorsRequest)
    - [ListSensorsResponse](#tetragon.ListSensorsResponse)
    - [ListTracingPoliciesRequest](#tetragon.ListTracingPoliciesRequest)
    - [ListTracingPoliciesResponse](#tetragon.ListTracingPoliciesResponse)
    - [RemoveSensorRequest](#tetragon.RemoveSensorRequest)
    - [RemoveSensorResponse](#tetragon.RemoveSensorResponse)
    - [SensorStatus](#tetragon.SensorStatus)
    - [TracingPolicyStatus](#tetragon.TracingPolicyStatus)
  
    - [TracingPolicyState](#tetragon.TracingPolicyState)
  
    - [FineGuidanceSensors](#tetragon.FineGuidanceSensors)
  
- [tetragon/stack.proto](#tetragon/stack.proto)
    - [StackAddress](#tetragon.StackAddress)
    - [StackTrace](#tetragon.StackTrace)
    - [StackTraceLabel](#tetragon.StackTraceLabel)
    - [StackTraceNode](#tetragon.StackTraceNode)
  
- [tetragon/tetragon.proto](#tetragon/tetragon.proto)
    - [BinaryProperties](#tetragon.BinaryProperties)
    - [Capabilities](#tetragon.Capabilities)
    - [Container](#tetragon.Container)
    - [CreateContainer](#tetragon.CreateContainer)
    - [CreateContainer.AnnotationsEntry](#tetragon.CreateContainer.AnnotationsEntry)
    - [FileProperties](#tetragon.FileProperties)
    - [GetHealthStatusRequest](#tetragon.GetHealthStatusRequest)
    - [GetHealthStatusResponse](#tetragon.GetHealthStatusResponse)
    - [HealthStatus](#tetragon.HealthStatus)
    - [Image](#tetragon.Image)
    - [InodeProperties](#tetragon.InodeProperties)
    - [KernelModule](#tetragon.KernelModule)
    - [KprobeArgument](#tetragon.KprobeArgument)
    - [KprobeBpfAttr](#tetragon.KprobeBpfAttr)
    - [KprobeBpfMap](#tetragon.KprobeBpfMap)
    - [KprobeCapability](#tetragon.KprobeCapability)
    - [KprobeCred](#tetragon.KprobeCred)
    - [KprobeFile](#tetragon.KprobeFile)
    - [KprobeLinuxBinprm](#tetragon.KprobeLinuxBinprm)
    - [KprobePath](#tetragon.KprobePath)
    - [KprobePerfEvent](#tetragon.KprobePerfEvent)
    - [KprobeSkb](#tetragon.KprobeSkb)
    - [KprobeSock](#tetragon.KprobeSock)
    - [KprobeTruncatedBytes](#tetragon.KprobeTruncatedBytes)
    - [KprobeUserNamespace](#tetragon.KprobeUserNamespace)
    - [Namespace](#tetragon.Namespace)
    - [Namespaces](#tetragon.Namespaces)
    - [Pod](#tetragon.Pod)
    - [Pod.PodLabelsEntry](#tetragon.Pod.PodLabelsEntry)
    - [Process](#tetragon.Process)
    - [ProcessCredentials](#tetragon.ProcessCredentials)
    - [ProcessExec](#tetragon.ProcessExec)
    - [ProcessExit](#tetragon.ProcessExit)
    - [ProcessKprobe](#tetragon.ProcessKprobe)
    - [ProcessLoader](#tetragon.ProcessLoader)
    - [ProcessTracepoint](#tetragon.ProcessTracepoint)
    - [ProcessUprobe](#tetragon.ProcessUprobe)
    - [RuntimeHookRequest](#tetragon.RuntimeHookRequest)
    - [RuntimeHookResponse](#tetragon.RuntimeHookResponse)
    - [StackTraceEntry](#tetragon.StackTraceEntry)
    - [Test](#tetragon.Test)
    - [UserNamespace](#tetragon.UserNamespace)
  
    - [HealthStatusResult](#tetragon.HealthStatusResult)
    - [HealthStatusType](#tetragon.HealthStatusType)
    - [KprobeAction](#tetragon.KprobeAction)
    - [TaintedBitsType](#tetragon.TaintedBitsType)
  
- [Scalar Value Types](#scalar-value-types)



<a name="tetragon/capabilities.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## tetragon/capabilities.proto


 


<a name="tetragon.CapabilitiesType"></a>

### CapabilitiesType


| Name | Number | Description |
| ---- | ------ | ----------- |
| CAP_CHOWN | 0 | In a system with the [_POSIX_CHOWN_RESTRICTED] option defined, this overrides the restriction of changing file ownership and group ownership. |
| DAC_OVERRIDE | 1 | Override all DAC access, including ACL execute access if [_POSIX_ACL] is defined. Excluding DAC access covered by CAP_LINUX_IMMUTABLE. |
| CAP_DAC_READ_SEARCH | 2 | Overrides all DAC restrictions regarding read and search on files and directories, including ACL restrictions if [_POSIX_ACL] is defined. Excluding DAC access covered by &#34;$1&#34;_LINUX_IMMUTABLE. |
| CAP_FOWNER | 3 | Overrides all restrictions about allowed operations on files, where file owner ID must be equal to the user ID, except where CAP_FSETID is applicable. It doesn&#39;t override MAC and DAC restrictions. |
| CAP_FSETID | 4 | Overrides the following restrictions that the effective user ID shall match the file owner ID when setting the S_ISUID and S_ISGID bits on that file; that the effective group ID (or one of the supplementary group IDs) shall match the file owner ID when setting the S_ISGID bit on that file; that the S_ISUID and S_ISGID bits are cleared on successful return from chown(2) (not implemented). |
| CAP_KILL | 5 | Overrides the restriction that the real or effective user ID of a process sending a signal must match the real or effective user ID of the process receiving the signal. |
| CAP_SETGID | 6 | Allows forged gids on socket credentials passing. |
| CAP_SETUID | 7 | Allows forged pids on socket credentials passing. |
| CAP_SETPCAP | 8 | Without VFS support for capabilities: Transfer any capability in your permitted set to any pid, remove any capability in your permitted set from any pid With VFS support for capabilities (neither of above, but) Add any capability from current&#39;s capability bounding set to the current process&#39; inheritable set Allow taking bits out of capability bounding set Allow modification of the securebits for a process |
| CAP_LINUX_IMMUTABLE | 9 | Allow modification of S_IMMUTABLE and S_APPEND file attributes |
| CAP_NET_BIND_SERVICE | 10 | Allows binding to ATM VCIs below 32 |
| CAP_NET_BROADCAST | 11 | Allow broadcasting, listen to multicast |
| CAP_NET_ADMIN | 12 | Allow activation of ATM control sockets |
| CAP_NET_RAW | 13 | Allow binding to any address for transparent proxying (also via NET_ADMIN) |
| CAP_IPC_LOCK | 14 | Allow mlock and mlockall (which doesn&#39;t really have anything to do with IPC) |
| CAP_IPC_OWNER | 15 | Override IPC ownership checks |
| CAP_SYS_MODULE | 16 | Insert and remove kernel modules - modify kernel without limit |
| CAP_SYS_RAWIO | 17 | Allow sending USB messages to any device via /dev/bus/usb |
| CAP_SYS_CHROOT | 18 | Allow use of chroot() |
| CAP_SYS_PTRACE | 19 | Allow ptrace() of any process |
| CAP_SYS_PACCT | 20 | Allow configuration of process accounting |
| CAP_SYS_ADMIN | 21 | Allow everything under CAP_BPF and CAP_PERFMON for backward compatibility |
| CAP_SYS_BOOT | 22 | Allow use of reboot() |
| CAP_SYS_NICE | 23 | Allow setting cpu affinity on other processes |
| CAP_SYS_RESOURCE | 24 | Control memory reclaim behavior |
| CAP_SYS_TIME | 25 | Allow setting the real-time clock |
| CAP_SYS_TTY_CONFIG | 26 | Allow vhangup() of tty |
| CAP_MKNOD | 27 | Allow the privileged aspects of mknod() |
| CAP_LEASE | 28 | Allow taking of leases on files |
| CAP_AUDIT_WRITE | 29 | Allow writing the audit log via unicast netlink socket |
| CAP_AUDIT_CONTROL | 30 | Allow configuration of audit via unicast netlink socket |
| CAP_SETFCAP | 31 | Set or remove capabilities on files |
| CAP_MAC_OVERRIDE | 32 | Override MAC access. The base kernel enforces no MAC policy. An LSM may enforce a MAC policy, and if it does and it chooses to implement capability based overrides of that policy, this is the capability it should use to do so. |
| CAP_MAC_ADMIN | 33 | Allow MAC configuration or state changes. The base kernel requires no MAC configuration. An LSM may enforce a MAC policy, and if it does and it chooses to implement capability based checks on modifications to that policy or the data required to maintain it, this is the capability it should use to do so. |
| CAP_SYSLOG | 34 | Allow configuring the kernel&#39;s syslog (printk behaviour) |
| CAP_WAKE_ALARM | 35 | Allow triggering something that will wake the system |
| CAP_BLOCK_SUSPEND | 36 | Allow preventing system suspends |
| CAP_AUDIT_READ | 37 | Allow reading the audit log via multicast netlink socket |
| CAP_PERFMON | 38 | Allow system performance and observability privileged operations using perf_events, i915_perf and other kernel subsystems |
| CAP_BPF | 39 | CAP_BPF allows the following BPF operations: - Creating all types of BPF maps - Advanced verifier features - Indirect variable access - Bounded loops - BPF to BPF function calls - Scalar precision tracking - Larger complexity limits - Dead code elimination - And potentially other features - Loading BPF Type Format (BTF) data - Retrieve xlated and JITed code of BPF programs - Use bpf_spin_lock() helper CAP_PERFMON relaxes the verifier checks further: - BPF progs can use of pointer-to-integer conversions - speculation attack hardening measures are bypassed - bpf_probe_read to read arbitrary kernel memory is allowed - bpf_trace_printk to print kernel memory is allowed CAP_SYS_ADMIN is required to use bpf_probe_write_user. CAP_SYS_ADMIN is required to iterate system wide loaded programs, maps, links, BTFs and convert their IDs to file descriptors. CAP_PERFMON and CAP_BPF are required to load tracing programs. CAP_NET_ADMIN and CAP_BPF are required to load networking programs. |
| CAP_CHECKPOINT_RESTORE | 40 | Allow writing to ns_last_pid |



<a name="tetragon.ProcessPrivilegesChanged"></a>

### ProcessPrivilegesChanged
Reasons of why the process privileges changed.

| Name | Number | Description |
| ---- | ------ | ----------- |
| PRIVILEGES_CHANGED_UNSET | 0 |  |
| PRIVILEGES_RAISED_EXEC_FILE_CAP | 1 | A privilege elevation happened due to the execution of a binary with file capability sets. The kernel supports associating capability sets with an executable file using `setcap` command. The file capability sets are stored in an extended attribute (see https://man7.org/linux/man-pages/man7/xattr.7.html) named `security.capability`. The file capability sets, in conjunction with the capability sets of the process, determine the process capabilities and privileges after the `execve` system call. For further reference, please check sections `File capability extended attribute versioning` and `Namespaced file capabilities` of the capabilities man pages: https://man7.org/linux/man-pages/man7/capabilities.7.html. The new granted capabilities can be listed inside the `process` object. |
| PRIVILEGES_RAISED_EXEC_FILE_SETUID | 2 | A privilege elevation happened due to the execution of a binary with set-user-ID to root. When a process with nonzero UIDs executes a binary with a set-user-ID to root also known as suid-root executable, then the kernel switches the effective user ID to 0 (root) which is a privilege elevation operation since it grants access to resources owned by the root user. The effective user ID is listed inside the `process_credentials` part of the `process` object. For further reading, section `Capabilities and execution of programs by root` of https://man7.org/linux/man-pages/man7/capabilities.7.html. Afterward the kernel recalculates the capability sets of the process and grants all capabilities in the permitted and effective capability sets, except those masked out by the capability bounding set. If the binary also have file capability sets then these bits are honored and the process gains just the capabilities granted by the file capability sets (i.e., not all capabilities, as it would occur when executing a set-user-ID to root binary that does not have any associated file capabilities). This is described in section `Set-user-ID-root programs that have file capabilities` of https://man7.org/linux/man-pages/man7/capabilities.7.html. The new granted capabilities can be listed inside the `process` object. There is one exception for the special treatments of set-user-ID to root execution receiving all capabilities, if the `SecBitNoRoot` bit of the Secure bits is set, then the kernel does not grant any capability. Please check section: `The securebits flags: establishing a capabilities-only environment` of the capabilities man pages: https://man7.org/linux/man-pages/man7/capabilities.7.html |
| PRIVILEGES_RAISED_EXEC_FILE_SETGID | 3 | A privilege elevation happened due to the execution of a binary with set-group-ID to root. When a process with nonzero GIDs executes a binary with a set-group-ID to root, the kernel switches the effective group ID to 0 (root) which is a privilege elevation operation since it grants access to resources owned by the root group. The effective group ID is listed inside the `process_credentials` part of the `process` object. |



<a name="tetragon.SecureBitsType"></a>

### SecureBitsType


| Name | Number | Description |
| ---- | ------ | ----------- |
| SecBitNotSet | 0 |  |
| SecBitNoRoot | 1 | When set UID 0 has no special privileges. When unset, inheritance of root-permissions and suid-root executable under compatibility mode is supported. If the effective uid of the new process is 0 then the effective and inheritable bitmasks of the executable file is raised. If the real uid is 0, the effective (legacy) bit of the executable file is raised. |
| SecBitNoRootLocked | 2 | Make bit-0 SecBitNoRoot immutable |
| SecBitNoSetUidFixup | 4 | When set, setuid to/from uid 0 does not trigger capability-&#34;fixup&#34;. When unset, to provide compatiblility with old programs relying on set*uid to gain/lose privilege, transitions to/from uid 0 cause capabilities to be gained/lost. |
| SecBitNoSetUidFixupLocked | 8 | Make bit-2 SecBitNoSetUidFixup immutable |
| SecBitKeepCaps | 16 | When set, a process can retain its capabilities even after transitioning to a non-root user (the set-uid fixup suppressed by bit 2). Bit-4 is cleared when a process calls exec(); setting both bit 4 and 5 will create a barrier through exec that no exec()&#39;d child can use this feature again. |
| SecBitKeepCapsLocked | 32 | Make bit-4 SecBitKeepCaps immutable |
| SecBitNoCapAmbientRaise | 64 | When set, a process cannot add new capabilities to its ambient set. |
| SecBitNoCapAmbientRaiseLocked | 128 | Make bit-6 SecBitNoCapAmbientRaise immutable |


 

 

 



<a name="tetragon/dns.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## tetragon/dns.proto



<a name="tetragon.DnsInfo"></a>

### DnsInfo



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| question_types | [uint32](#uint32) | repeated | **Deprecated.** deprecated in favor of query_types |
| answer_types | [uint32](#uint32) | repeated | **Deprecated.** deprecated in favor of response_types |
| rcode | [int32](#int32) |  | **Deprecated.** deprecated in favor of return_code |
| names | [string](#string) | repeated |  |
| ips | [string](#string) | repeated |  |
| query | [string](#string) |  | **Deprecated.** unused field, deprecated in favor of names and query_types |
| response | [bool](#bool) |  |  |
| return_code | [google.protobuf.Int32Value](#google.protobuf.Int32Value) |  |  |
| query_types | [DnsType](#tetragon.DnsType) | repeated |  |
| response_types | [DnsType](#tetragon.DnsType) | repeated |  |






<a name="tetragon.ProcessDns"></a>

### ProcessDns



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  |  |
| socket | [SockInfo](#tetragon.SockInfo) |  |  |
| dns | [DnsInfo](#tetragon.DnsInfo) |  |  |
| destination_names | [string](#string) | repeated | **Deprecated.** deprecated in favor of socket.destination_names. |
| destination_pod | [Pod](#tetragon.Pod) |  | **Deprecated.** deprecated in favor of socket.destination_pod |
| parent | [Process](#tetragon.Process) |  |  |





 


<a name="tetragon.DnsType"></a>

### DnsType


| Name | Number | Description |
| ---- | ------ | ----------- |
| DNS_TYPE_UNDEF | 0 |  |
| A | 1 |  |
| NS | 2 |  |
| CNAME | 5 |  |
| SOA | 6 |  |
| PTR | 12 |  |
| MX | 15 |  |
| TXT | 16 |  |
| AAAA | 28 |  |
| SRV | 33 |  |
| OPT | 41 |  |
| WKS | 11 |  |
| HINFO | 13 |  |
| MINFO | 14 |  |
| AXFR | 252 |  |
| ALL | 255 |  |


 

 

 



<a name="tetragon/events.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## tetragon/events.proto



<a name="tetragon.AggregationInfo"></a>

### AggregationInfo
AggregationInfo contains information about aggregation results.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| count | [uint64](#uint64) |  | Total count of events in this aggregation time window. |






<a name="tetragon.AggregationOptions"></a>

### AggregationOptions
AggregationOptions defines configuration options for aggregating events.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| window_size | [google.protobuf.Duration](#google.protobuf.Duration) |  | Aggregation window size. Defaults to 15 seconds if this field is not set. |
| channel_buffer_size | [uint64](#uint64) |  | Size of the buffer for the aggregator to receive incoming events. If the buffer becomes full, the aggregator will log a warning and start dropping incoming events. |






<a name="tetragon.FieldFilter"></a>

### FieldFilter



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| event_set | [EventType](#tetragon.EventType) | repeated | Event types to filter or undefined to filter over all event types. |
| fields | [google.protobuf.FieldMask](#google.protobuf.FieldMask) |  | Fields to include or exclude. |
| action | [FieldFilterAction](#tetragon.FieldFilterAction) |  | Whether to include or exclude fields. |
| invert_event_set | [google.protobuf.BoolValue](#google.protobuf.BoolValue) |  | Whether or not the event set filter should be inverted. |






<a name="tetragon.Filter"></a>

### Filter



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| binary_regex | [string](#string) | repeated |  |
| namespace | [string](#string) | repeated |  |
| health_check | [google.protobuf.BoolValue](#google.protobuf.BoolValue) |  |  |
| pid | [uint32](#uint32) | repeated |  |
| pid_set | [uint32](#uint32) | repeated |  |
| event_set | [EventType](#tetragon.EventType) | repeated |  |
| pod_regex | [string](#string) | repeated | A series of regexes for filtering over pod name |
| arguments_regex | [string](#string) | repeated | Filter by process.arguments field using RE2 regular expression syntax: https://github.com/google/re2/wiki/Syntax |
| labels | [string](#string) | repeated | Filter events by pod labels using Kubernetes label selector syntax: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors Note that this filter never matches events without the pod field (i.e. host process events). |
| policy_names | [string](#string) | repeated | Filter events by tracing policy names |
| source_ip_cidr | [string](#string) | repeated | Filter by source_ip field using an address range specified using CIDR notation.

Example: {&#34;event_set&#34;: [&#34;PROCESS_ACCEPT&#34;], &#34;source_ip_cidr&#34;: [&#34;127.0.0.0/16&#34;]} |
| destination_ip_cidr | [string](#string) | repeated | Filter by destination_ip field using an address range specified using CIDR notation.

Example: {&#34;event_set&#34;: [&#34;PROCESS_CLOSE&#34;], &#34;destination_ip_cidr&#34;: [&#34;8.8.0.0/16&#34;]} |
| ip_cidr | [string](#string) | repeated | Filter by IP field using an address range specified using CIDR notation. This includes source_ip, destination_ip, and ProcessListen&#39;s ip field.

Example 1: {&#34;event_set&#34;: [&#34;PROCESS_ACCEPT&#34;], ip_cidr&#34;: [&#34;127.0.0.1&#34;, &#34;8.8.0.0/16&#34;]} Example 2: {&#34;event_set&#34;: [&#34;PROCESS_LISTEN&#34;], ip_cidr&#34;: [&#34;127.0.0.0/16&#34;]} |
| uri_regex | [string](#string) | repeated | Filter by http.request.uri field using RE2 regular expression syntax: https://github.com/google/re2/wiki/Syntax |
| sni_regex | [string](#string) | repeated | Filter by tls.sni_name field using RE2 regular expression syntax: https://github.com/google/re2/wiki/Syntax |
| destination_names_regex | [string](#string) | repeated | Filter by destination_names field using RE2 regular expression syntax: https://github.com/google/re2/wiki/Syntax |
| destination_pod_regex | [string](#string) | repeated | Filter by destination_pod.name field using RE2 regular expression syntax: https://github.com/google/re2/wiki/Syntax |
| dns_names_regex | [string](#string) | repeated | Filter by process_dns.dns.names field using RE2 regular expression syntax: https://github.com/google/re2/wiki/Syntax |
| host_regex | [string](#string) | repeated | Filter by process_http.http.request.host field using RE2 regular expression syntax: https://github.com/google/re2/wiki/Syntax |






<a name="tetragon.GetEventsRequest"></a>

### GetEventsRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| allow_list | [Filter](#tetragon.Filter) | repeated | allow_list specifies a list of filters to apply to only return certain events. If multiple filters are specified, at least one of them has to match for an event to be included in the results. |
| deny_list | [Filter](#tetragon.Filter) | repeated | deny_list specifies a list of filters to apply to exclude certain events from the results. If multiple filters are specified, at least one of them has to match for an event to be excluded.

If both allow_list and deny_list are specified, the results contain the set difference allow_list - deny_list. |
| aggregation_options | [AggregationOptions](#tetragon.AggregationOptions) |  | aggregation_options configures aggregation options for this request. If this field is not set, responses will not be aggregated.

Note that currently only process_accept and process_connect events are aggregated. Other events remain unaggregated. |
| field_filters | [FieldFilter](#tetragon.FieldFilter) | repeated | Fields to include or exclude for events in the GetEventsResponse. Omitting this field implies that all fields will be included. Exclusion always takes precedence over inclusion in the case of conflicts. |






<a name="tetragon.GetEventsResponse"></a>

### GetEventsResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process_exec | [ProcessExec](#tetragon.ProcessExec) |  |  |
| process_connect | [ProcessConnect](#tetragon.ProcessConnect) |  |  |
| process_listen | [ProcessListen](#tetragon.ProcessListen) |  |  |
| tls | [Tls](#tetragon.Tls) |  |  |
| process_exit | [ProcessExit](#tetragon.ProcessExit) |  |  |
| process_close | [ProcessClose](#tetragon.ProcessClose) |  |  |
| process_accept | [ProcessAccept](#tetragon.ProcessAccept) |  |  |
| process_kprobe | [ProcessKprobe](#tetragon.ProcessKprobe) |  |  |
| process_tracepoint | [ProcessTracepoint](#tetragon.ProcessTracepoint) |  |  |
| process_sock_stats | [ProcessSockStats](#tetragon.ProcessSockStats) |  |  |
| process_http | [ProcessHttp](#tetragon.ProcessHttp) |  |  |
| interface_stats | [InterfaceStats](#tetragon.InterfaceStats) |  |  |
| process_dns | [ProcessDns](#tetragon.ProcessDns) |  |  |
| process_network_burst | [ProcessNetworkBurst](#tetragon.ProcessNetworkBurst) |  |  |
| process_file | [ProcessFile](#tetragon.ProcessFile) |  |  |
| process_ip_error | [ProcessIpError](#tetragon.ProcessIpError) |  |  |
| process_loader | [ProcessLoader](#tetragon.ProcessLoader) |  |  |
| process_network_watermark | [ProcessNetworkWatermark](#tetragon.ProcessNetworkWatermark) |  |  |
| process_uprobe | [ProcessUprobe](#tetragon.ProcessUprobe) |  |  |
| process_udp_seq_check_error | [ProcessUdpSeqCheckError](#tetragon.ProcessUdpSeqCheckError) |  |  |
| process_file_exec | [ProcessFileExec](#tetragon.ProcessFileExec) |  |  |
| process_icmp | [ProcessIcmp](#tetragon.ProcessIcmp) |  |  |
| process_rawsock_create | [ProcessRawsockCreate](#tetragon.ProcessRawsockCreate) |  |  |
| process_rawsock_close | [ProcessRawsockClose](#tetragon.ProcessRawsockClose) |  |  |
| process_sandbox_syscall | [ProcessSandboxSyscall](#tetragon.ProcessSandboxSyscall) |  |  |
| test | [Test](#tetragon.Test) |  |  |
| rate_limit_info | [RateLimitInfo](#tetragon.RateLimitInfo) |  |  |
| node_name | [string](#string) |  | Name of the node where this event was observed. |
| time | [google.protobuf.Timestamp](#google.protobuf.Timestamp) |  | Timestamp at which this event was observed.

For an aggregated response, this field to set to the timestamp at which the event was observed for the first time in a given aggregation time window. |
| aggregation_info | [AggregationInfo](#tetragon.AggregationInfo) |  | aggregation_info contains information about aggregation results. This field is set only for aggregated responses. |






<a name="tetragon.RateLimitInfo"></a>

### RateLimitInfo



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| number_of_dropped_process_events | [uint64](#uint64) |  |  |





 


<a name="tetragon.EventType"></a>

### EventType
Represents the type of a Tetragon event.

NOTE: EventType constants must be in sync with the numbers used in the
GetEventsResponse event oneof.

| Name | Number | Description |
| ---- | ------ | ----------- |
| UNDEF | 0 |  |
| PROCESS_EXEC | 1 |  |
| PROCESS_CONNECT | 2 |  |
| PROCESS_LISTEN | 3 |  |
| PROCESS_TLS | 4 |  |
| TLS | 4 | TLS is an alias for PROCESS_TLS |
| PROCESS_EXIT | 5 |  |
| PROCESS_CLOSE | 6 |  |
| PROCESS_ACCEPT | 7 |  |
| PROCESS_KPROBE | 9 |  |
| PROCESS_TRACEPOINT | 10 |  |
| PROCESS_SOCKSTATS | 11 |  |
| PROCESS_SOCK_STATS | 11 | PROCESS_SOCK_STATS is an alias for PROCESS_SOCKSTATS |
| PROCESS_HTTP | 12 |  |
| INTERFACE_STATS | 13 |  |
| PROCESS_DNS | 14 |  |
| PROCESS_NETWORK_BURST | 15 |  |
| PROCESS_FILE | 16 |  |
| PROCESS_IP_ERROR | 17 |  |
| PROCESS_LOADER | 18 |  |
| PROCESS_NETWORK_WATERMARK | 19 |  |
| PROCESS_UPROBE | 20 |  |
| PROCESS_UDP_SEQ_CHECK_ERROR | 21 |  |
| PROCESS_FILE_EXEC | 22 |  |
| PROCESS_ICMP | 23 |  |
| PROCESS_RAWSOCK_CREATE | 24 |  |
| PROCESS_RAWSOCK_CLOSE | 25 |  |
| PROCESS_SANDBOX_SYSCALL | 26 |  |
| TEST | 40000 |  |
| RATE_LIMIT_INFO | 40001 |  |



<a name="tetragon.FieldFilterAction"></a>

### FieldFilterAction
Determins the behaviour of a field filter

| Name | Number | Description |
| ---- | ------ | ----------- |
| INCLUDE | 0 |  |
| EXCLUDE | 1 |  |


 

 

 



<a name="tetragon/fgs.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## tetragon/fgs.proto



<a name="tetragon.AttrArg"></a>

### AttrArg



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| file | [FileDetails](#tetragon.FileDetails) |  |  |
| attr | [FileAttr](#tetragon.FileAttr) |  |  |
| mnt_ns | [Namespace](#tetragon.Namespace) |  |  |






<a name="tetragon.AttrChange"></a>

### AttrChange



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| new | [string](#string) |  |  |
| old | [string](#string) |  |  |






<a name="tetragon.FileArgument"></a>

### FileArgument



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| generic_arg | [GenericFileArg](#tetragon.GenericFileArg) |  |  |
| rename_arg | [RenameFileArg](#tetragon.RenameFileArg) |  |  |
| readdir_arg | [ReadDirArg](#tetragon.ReadDirArg) |  |  |
| attr_arg | [AttrArg](#tetragon.AttrArg) |  |  |






<a name="tetragon.FileAttr"></a>

### FileAttr



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| permissions | [AttrChange](#tetragon.AttrChange) |  |  |
| uid | [AttrChange](#tetragon.AttrChange) |  |  |
| gid | [AttrChange](#tetragon.AttrChange) |  |  |






<a name="tetragon.FileDetails"></a>

### FileDetails



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| str | [string](#string) |  |  |
| inode | [Inode](#tetragon.Inode) |  |  |
| parent_inode | [Inode](#tetragon.Inode) |  |  |
| location | [FileLocation](#tetragon.FileLocation) |  |  |






<a name="tetragon.FileDigest"></a>

### FileDigest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| algo | [DigestAlgo](#tetragon.DigestAlgo) |  |  |
| hash | [string](#string) |  |  |
| error | [int64](#int64) |  |  |






<a name="tetragon.FileIO"></a>

### FileIO



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| offset | [string](#string) |  |  |
| size | [string](#string) |  |  |






<a name="tetragon.FileLocation"></a>

### FileLocation



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [FileScope](#tetragon.FileScope) |  |  |
| container_id | [string](#string) |  | only valid if type == CONTAINER_FILE_{LOCAL, REMOTE} |
| pod | [Pod](#tetragon.Pod) |  | only valid if type == CONTAINER_FILE_REMOTE |






<a name="tetragon.FileSystem"></a>

### FileSystem



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| dev | [string](#string) |  |  |
| id | [string](#string) |  |  |
| uuid | [string](#string) |  |  |






<a name="tetragon.GenericFileArg"></a>

### GenericFileArg



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| file | [FileDetails](#tetragon.FileDetails) |  |  |
| io | [FileIO](#tetragon.FileIO) |  | **Deprecated.**  |
| mnt_ns | [Namespace](#tetragon.Namespace) |  |  |
| digest | [FileDigest](#tetragon.FileDigest) |  |  |






<a name="tetragon.Histogram"></a>

### Histogram



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| buckets | [HistogramBucket](#tetragon.HistogramBucket) | repeated |  |
| sum | [uint64](#uint64) |  |  |






<a name="tetragon.HistogramBucket"></a>

### HistogramBucket



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| percentile | [uint32](#uint32) |  |  |
| size | [uint32](#uint32) |  |  |
| count | [uint64](#uint64) |  |  |






<a name="tetragon.HttpHeader"></a>

### HttpHeader
HTTP PARSER


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| value | [string](#string) |  |  |






<a name="tetragon.HttpInfo"></a>

### HttpInfo



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| request | [HttpRequest](#tetragon.HttpRequest) |  |  |
| response | [HttpResponse](#tetragon.HttpResponse) |  |  |
| latency | [google.protobuf.Duration](#google.protobuf.Duration) |  |  |






<a name="tetragon.HttpRequest"></a>

### HttpRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| timestamp | [google.protobuf.Timestamp](#google.protobuf.Timestamp) |  |  |
| method | [string](#string) |  |  |
| uri | [string](#string) |  |  |
| version | [string](#string) |  |  |
| host | [string](#string) |  |  |
| agent | [string](#string) |  |  |
| content_length | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| headers | [HttpHeader](#tetragon.HttpHeader) | repeated |  |
| flags | [string](#string) |  |  |
| transfer_encoding | [string](#string) |  |  |






<a name="tetragon.HttpResponse"></a>

### HttpResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| timestamp | [google.protobuf.Timestamp](#google.protobuf.Timestamp) |  |  |
| version | [string](#string) |  |  |
| code | [uint32](#uint32) |  |  |
| reason | [string](#string) |  |  |
| content_length | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| headers | [HttpHeader](#tetragon.HttpHeader) | repeated |  |
| flags | [string](#string) |  |  |
| transfer_encoding | [string](#string) |  |  |






<a name="tetragon.Inode"></a>

### Inode



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| number | [uint64](#uint64) |  |  |
| fs | [FileSystem](#tetragon.FileSystem) |  |  |






<a name="tetragon.InterfaceStats"></a>

### InterfaceStats



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| interface_name | [string](#string) |  |  |
| interface_ifindex | [uint32](#uint32) |  |  |
| bytes_sent | [uint64](#uint64) |  |  |
| bytes_received | [uint64](#uint64) |  |  |
| packets_sent | [uint64](#uint64) |  |  |
| packets_received | [uint64](#uint64) |  |  |
| tx_errors | [uint64](#uint64) |  |  |
| rx_errors | [uint64](#uint64) |  |  |
| tx_drops | [uint64](#uint64) |  |  |
| rx_drops | [uint64](#uint64) |  |  |
| pod | [Pod](#tetragon.Pod) |  |  |
| netns | [string](#string) |  |  |
| container_name | [string](#string) |  |  |
| qlen | [Histogram](#tetragon.Histogram) |  |  |






<a name="tetragon.ProcessAccept"></a>

### ProcessAccept



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  |  |
| parent | [Process](#tetragon.Process) |  |  |
| source_ip | [string](#string) |  |  |
| source_port | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| destination_ip | [string](#string) |  |  |
| destination_port | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| destination_names | [string](#string) | repeated |  |
| sock_cookie | [uint64](#uint64) |  |  |
| destination_pod | [Pod](#tetragon.Pod) |  |  |
| protocol | [SocketProtocol](#tetragon.SocketProtocol) |  |  |






<a name="tetragon.ProcessClose"></a>

### ProcessClose



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  |  |
| parent | [Process](#tetragon.Process) |  |  |
| source_ip | [string](#string) |  |  |
| source_port | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| destination_ip | [string](#string) |  |  |
| destination_port | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| destination_names | [string](#string) | repeated |  |
| sock_cookie | [uint64](#uint64) |  |  |
| stats | [SocketStats](#tetragon.SocketStats) |  |  |
| destination_pod | [Pod](#tetragon.Pod) |  |  |
| protocol | [SocketProtocol](#tetragon.SocketProtocol) |  |  |
| socket_type | [string](#string) |  |  |
| duration | [google.protobuf.Duration](#google.protobuf.Duration) |  |  |






<a name="tetragon.ProcessConnect"></a>

### ProcessConnect



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  |  |
| parent | [Process](#tetragon.Process) |  |  |
| source_ip | [string](#string) |  |  |
| source_port | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| destination_ip | [string](#string) |  |  |
| destination_port | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| destination_names | [string](#string) | repeated |  |
| sock_cookie | [uint64](#uint64) |  |  |
| destination_pod | [Pod](#tetragon.Pod) |  |  |
| protocol | [SocketProtocol](#tetragon.SocketProtocol) |  |  |






<a name="tetragon.ProcessFile"></a>

### ProcessFile



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  |  |
| parent | [Process](#tetragon.Process) |  |  |
| action | [FileAction](#tetragon.FileAction) |  |  |
| args | [FileArgument](#tetragon.FileArgument) |  |  |
| permissions | [string](#string) |  |  |
| uid | [string](#string) |  |  |
| gid | [string](#string) |  |  |
| time | [google.protobuf.Timestamp](#google.protobuf.Timestamp) |  |  |
| hook | [string](#string) |  |  |
| operation | [FileOperation](#tetragon.FileOperation) | repeated |  |






<a name="tetragon.ProcessFileExec"></a>

### ProcessFileExec
ProcessFileExec events provide (additional to ProcessExec) information about files being executed.
They are configured in the &#34;exec:&#34; section of the TracingPolicy.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  |  |
| parent | [Process](#tetragon.Process) |  |  |
| file | [FileDetails](#tetragon.FileDetails) |  |  |
| digest | [FileDigest](#tetragon.FileDigest) |  |  |
| operations | [FileOperation](#tetragon.FileOperation) | repeated |  |






<a name="tetragon.ProcessHttp"></a>

### ProcessHttp



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  |  |
| socket | [SockInfo](#tetragon.SockInfo) |  |  |
| http | [HttpInfo](#tetragon.HttpInfo) |  |  |
| destination_names | [string](#string) | repeated | **Deprecated.** deprecated in favor of socket.destination_names. |
| destination_pod | [Pod](#tetragon.Pod) |  | **Deprecated.** deprecated in favor of socket.destination_pod |
| parent | [Process](#tetragon.Process) |  |  |






<a name="tetragon.ProcessIcmp"></a>

### ProcessIcmp



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  |  |
| parent | [Process](#tetragon.Process) |  |  |
| source_ip | [string](#string) |  |  |
| destination_ip | [string](#string) |  |  |
| destination_names | [string](#string) | repeated |  |
| sock_cookie | [uint64](#uint64) |  |  |
| destination_pod | [Pod](#tetragon.Pod) |  |  |
| protocol | [SocketProtocol](#tetragon.SocketProtocol) |  |  |
| icmp_type | [string](#string) |  |  |
| icmp_code | [string](#string) |  |  |
| icmp_type_value | [uint32](#uint32) |  |  |
| icmp_code_value | [uint32](#uint32) |  |  |
| identifier | [uint32](#uint32) |  |  |
| sequence_number | [uint32](#uint32) |  |  |
| icmp_data_len | [uint32](#uint32) |  |  |
| direction | [string](#string) |  |  |
| icmp_ip_protocol | [SocketProtocol](#tetragon.SocketProtocol) |  |  |
| icmp_ip_port | [uint32](#uint32) |  |  |
| icmp_ip_ttl | [uint32](#uint32) |  |  |
| icmp_ip_pointer | [uint32](#uint32) |  |  |
| icmp_ip_gateway | [string](#string) |  |  |






<a name="tetragon.ProcessIpError"></a>

### ProcessIpError



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  |  |
| parent | [Process](#tetragon.Process) |  |  |
| source_ip | [string](#string) |  |  |
| destination_ip | [string](#string) |  |  |
| version | [string](#string) |  |  |
| sock_cookie | [uint64](#uint64) |  |  |
| destination_pod | [Pod](#tetragon.Pod) |  |  |
| details | [string](#string) |  |  |
| send | [string](#string) |  |  |
| version_byte | [uint64](#uint64) |  |  |
| data | [uint64](#uint64) |  |  |






<a name="tetragon.ProcessListen"></a>

### ProcessListen



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  |  |
| parent | [Process](#tetragon.Process) |  |  |
| ip | [string](#string) |  |  |
| port | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| sock_cookie | [uint64](#uint64) |  |  |
| protocol | [SocketProtocol](#tetragon.SocketProtocol) |  |  |






<a name="tetragon.ProcessNetworkBurst"></a>

### ProcessNetworkBurst



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  |  |
| parent | [Process](#tetragon.Process) |  |  |
| protocol | [string](#string) |  |  |
| direction | [string](#string) |  |  |
| burst_state | [string](#string) |  |  |
| window_size | [uint64](#uint64) |  |  |
| hist_avg | [uint64](#uint64) |  |  |
| hist_trigger | [uint64](#uint64) |  |  |
| window_avg | [uint64](#uint64) |  |  |






<a name="tetragon.ProcessNetworkWatermark"></a>

### ProcessNetworkWatermark



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  |  |
| parent | [Process](#tetragon.Process) |  |  |
| protocol | [string](#string) |  |  |
| direction | [string](#string) |  |  |
| watermarks_state | [string](#string) |  |  |
| watermarks_type | [string](#string) |  |  |
| window_size | [uint64](#uint64) |  |  |
| hist_avg | [uint64](#uint64) |  |  |
| hist_burst_trigger | [uint64](#uint64) |  |  |
| hist_dip_trigger | [uint64](#uint64) |  |  |
| window_avg | [uint64](#uint64) |  |  |






<a name="tetragon.ProcessRawsockClose"></a>

### ProcessRawsockClose



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  |  |
| parent | [Process](#tetragon.Process) |  |  |
| sock_cookie | [uint64](#uint64) |  |  |
| duration | [google.protobuf.Duration](#google.protobuf.Duration) |  |  |






<a name="tetragon.ProcessRawsockCreate"></a>

### ProcessRawsockCreate



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  |  |
| parent | [Process](#tetragon.Process) |  |  |
| sock_cookie | [uint64](#uint64) |  |  |






<a name="tetragon.ProcessSockStats"></a>

### ProcessSockStats



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  |  |
| parent | [Process](#tetragon.Process) |  |  |
| socket | [SockInfo](#tetragon.SockInfo) |  |  |
| stats | [SocketStats](#tetragon.SocketStats) |  |  |






<a name="tetragon.ProcessUdpSeqCheckError"></a>

### ProcessUdpSeqCheckError



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  |  |
| parent | [Process](#tetragon.Process) |  |  |
| socket | [SockInfo](#tetragon.SockInfo) |  |  |
| application_id | [uint64](#uint64) |  |  |
| app_specific_id | [uint64](#uint64) |  |  |
| seq_num_expected | [uint64](#uint64) |  |  |
| seq_num_received | [uint64](#uint64) |  |  |






<a name="tetragon.ReadDirArg"></a>

### ReadDirArg



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| file | [FileDetails](#tetragon.FileDetails) |  |  |
| mnt_ns | [Namespace](#tetragon.Namespace) |  |  |






<a name="tetragon.RenameFileArg"></a>

### RenameFileArg



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| src | [FileDetails](#tetragon.FileDetails) |  |  |
| dst | [FileDetails](#tetragon.FileDetails) |  |  |
| mnt_ns | [Namespace](#tetragon.Namespace) |  |  |
| flags | [string](#string) | repeated |  |






<a name="tetragon.SockInfo"></a>

### SockInfo



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| source_ip | [string](#string) |  |  |
| source_port | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| destination_ip | [string](#string) |  |  |
| destination_port | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| sock_cookie | [uint64](#uint64) |  |  |
| protocol | [SocketProtocol](#tetragon.SocketProtocol) |  |  |
| destination_names | [string](#string) | repeated |  |
| destination_pod | [Pod](#tetragon.Pod) |  |  |






<a name="tetragon.SocketStats"></a>

### SocketStats



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bytes_sent | [uint64](#uint64) |  |  |
| bytes_received | [uint64](#uint64) |  |  |
| segs_in | [uint32](#uint32) |  |  |
| segs_out | [uint32](#uint32) |  |  |
| srtt | [uint32](#uint32) |  | TCP specific: |
| retransmits_bytes | [uint64](#uint64) |  |  |
| retransmits_segs | [uint32](#uint32) |  |  |
| to_zero_window | [uint32](#uint32) |  |  |
| sk_drop | [uint32](#uint32) |  |  |
| bytes_consumed | [uint64](#uint64) |  | UDP specific: |
| bytes_submitted | [uint64](#uint64) |  |  |
| segs_consumed | [uint32](#uint32) |  |  |
| segs_submitted | [uint32](#uint32) |  |  |
| skb_consume_misses | [uint32](#uint32) |  |  |
| rtt | [Histogram](#tetragon.Histogram) |  | TCP RTT Histogram: |
| latency | [Histogram](#tetragon.Histogram) |  | TCP/UDP Latency Histogram: |






<a name="tetragon.Tls"></a>

### Tls



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  |  |
| source_ip | [string](#string) |  |  |
| source_port | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| destination_ip | [string](#string) |  |  |
| destination_port | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| negotiated_version | [string](#string) |  |  |
| supported_versions | [string](#string) |  |  |
| sni_type | [string](#string) |  |  |
| sni_name | [string](#string) |  |  |
| cipher | [string](#string) |  |  |
| client_flags | [string](#string) |  |  |
| server_flags | [string](#string) |  |  |
| client_version | [string](#string) |  |  |
| server_version | [string](#string) |  |  |
| client_alert | [string](#string) |  |  |
| server_alert | [string](#string) |  |  |
| client_session | [string](#string) |  |  |
| server_session | [string](#string) |  |  |
| certificates | [string](#string) | repeated |  |
| certificate_error | [TlsCertificateError](#tetragon.TlsCertificateError) |  |  |
| parser_state_next | [uint32](#uint32) |  | **Deprecated.**  |
| parser_state_needed | [uint32](#uint32) |  | **Deprecated.**  |
| parser_state_csize | [uint32](#uint32) |  | **Deprecated.**  |
| parser_state_skblen | [uint32](#uint32) |  | **Deprecated.**  |
| parser_internal_state | [string](#string) |  |  |
| parent | [Process](#tetragon.Process) |  |  |





 


<a name="tetragon.DigestAlgo"></a>

### DigestAlgo
from https://elixir.bootlin.com/linux/v6.2.16/source/include/uapi/linux/hash_info.h

| Name | Number | Description |
| ---- | ------ | ----------- |
| HASH_ALGO_MD4 | 0 |  |
| HASH_ALGO_MD5 | 1 |  |
| HASH_ALGO_SHA1 | 2 |  |
| HASH_ALGO_RIPE_MD_160 | 3 |  |
| HASH_ALGO_SHA256 | 4 |  |
| HASH_ALGO_SHA384 | 5 |  |
| HASH_ALGO_SHA512 | 6 |  |
| HASH_ALGO_SHA224 | 7 |  |
| HASH_ALGO_RIPE_MD_128 | 8 |  |
| HASH_ALGO_RIPE_MD_256 | 9 |  |
| HASH_ALGO_RIPE_MD_320 | 10 |  |
| HASH_ALGO_WP_256 | 11 |  |
| HASH_ALGO_WP_384 | 12 |  |
| HASH_ALGO_WP_512 | 13 |  |
| HASH_ALGO_TGR_128 | 14 |  |
| HASH_ALGO_TGR_160 | 15 |  |
| HASH_ALGO_TGR_192 | 16 |  |
| HASH_ALGO_SM3_256 | 17 |  |
| HASH_ALGO_STREEBOG_256 | 18 |  |
| HASH_ALGO_STREEBOG_512 | 19 |  |
| HASH_ALGO__LAST | 20 |  |



<a name="tetragon.FileAction"></a>

### FileAction


| Name | Number | Description |
| ---- | ------ | ----------- |
| FILE_INVALID | 0 |  |
| FILE_WRITE | 1 |  |
| FILE_READ | 2 |  |
| FILE_DELETE | 3 |  |
| FILE_CREATE | 4 |  |
| FILE_RMDIR | 5 |  |
| FILE_MKDIR | 6 |  |
| FILE_RENAME | 7 |  |
| FILE_READDIR | 8 |  |
| FILE_CHATTR | 9 |  |
| FILE_EXEC | 10 |  |



<a name="tetragon.FileOperation"></a>

### FileOperation


| Name | Number | Description |
| ---- | ------ | ----------- |
| FILE_OP_UNKNOWN | 0 |  |
| FILE_OP_POST | 1 |  |
| FILE_OP_BLOCK | 2 |  |



<a name="tetragon.FileScope"></a>

### FileScope


| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN_FILE | 0 |  |
| HOST_FILE | 1 | HOST_FILE means that the file is monitored as a host file, and the access happened from a container or the host |
| CONTAINER_FILE_LOCAL | 2 | CONTAINER_FILE_LOCAL means that the file is monitored as a container file, and the access happened from the same container |
| CONTAINER_FILE_REMOTE | 3 | CONTAINER_FILE_REMOTE means that the file is monitored as a container file, and the access happened from a different container or the host |



<a name="tetragon.SocketProtocol"></a>

### SocketProtocol


| Name | Number | Description |
| ---- | ------ | ----------- |
| UNKNOWN | 0 |  |
| ICMP | 1 |  |
| TCP | 6 |  |
| UDP | 17 |  |
| ICMPV6 | 58 |  |



<a name="tetragon.TlsCertificateError"></a>

### TlsCertificateError


| Name | Number | Description |
| ---- | ------ | ----------- |
| TLS_CERT_ERROR_UNDEF | 0 |  |
| TLS_CERT_ERROR_UNKNOWN | 1 |  |
| TLS_CERT_ERROR_TOO_LARGE | 2 |  |
| TLS_CERT_ERROR_GET_DATA_HDR | 3 |  |
| TLS_CERT_ERROR_NO_BUFFER | 4 |  |
| TLS_CERT_ERROR_COPY | 5 |  |
| TLS_CERT_ERROR_LENGTH_READ | 6 |  |
| TLS_CERT_ERROR_CERT_READ | 7 |  |
| TLS_CERT_ERROR_CERT_PARTIAL | 8 |  |
| TLS_CERT_ERROR_PARSE_X509 | 9 |  |
| TLS_CERT_ERROR_MISSING_CODE | 10 |  |
| TLS_CERT_ERROR_GET_DATA_CERT | 11 |  |
| TLS_CERT_ERROR_GET_DATA_MORECERT | 12 |  |
| TLS_CERT_ERROR_COPY_CERT | 13 |  |
| TLS_CERT_ERROR_COPY_MORE_CERT | 14 |  |
| TLS_CERT_ERROR_BAD_HEADER | 15 |  |
| TLS_CERT_ERROR_MISSING_ERROR | 16 |  |
| TLS_CERT_ERROR_SPURIOUS_CERTS | 17 |  |


 

 

 



<a name="tetragon/sandbox.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## tetragon/sandbox.proto



<a name="tetragon.ProcessSandboxSyscall"></a>

### ProcessSandboxSyscall



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  |  |
| parent | [Process](#tetragon.Process) |  |  |
| name | [string](#string) |  | syscall name |





 

 

 

 



<a name="tetragon/sensors.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## tetragon/sensors.proto



<a name="tetragon.AddTracingPolicyRequest"></a>

### AddTracingPolicyRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| yaml | [string](#string) |  |  |






<a name="tetragon.AddTracingPolicyResponse"></a>

### AddTracingPolicyResponse







<a name="tetragon.DeleteTracingPolicyRequest"></a>

### DeleteTracingPolicyRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |






<a name="tetragon.DeleteTracingPolicyResponse"></a>

### DeleteTracingPolicyResponse







<a name="tetragon.DisableSensorRequest"></a>

### DisableSensorRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |






<a name="tetragon.DisableSensorResponse"></a>

### DisableSensorResponse







<a name="tetragon.DisableTracingPolicyRequest"></a>

### DisableTracingPolicyRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |






<a name="tetragon.DisableTracingPolicyResponse"></a>

### DisableTracingPolicyResponse







<a name="tetragon.EnableSensorRequest"></a>

### EnableSensorRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |






<a name="tetragon.EnableSensorResponse"></a>

### EnableSensorResponse







<a name="tetragon.EnableTracingPolicyRequest"></a>

### EnableTracingPolicyRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |






<a name="tetragon.EnableTracingPolicyResponse"></a>

### EnableTracingPolicyResponse







<a name="tetragon.GetStackTraceTreeRequest"></a>

### GetStackTraceTreeRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |






<a name="tetragon.GetStackTraceTreeResponse"></a>

### GetStackTraceTreeResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| root | [StackTraceNode](#tetragon.StackTraceNode) |  |  |






<a name="tetragon.GetVersionRequest"></a>

### GetVersionRequest







<a name="tetragon.GetVersionResponse"></a>

### GetVersionResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| version | [string](#string) |  |  |






<a name="tetragon.ListSensorsRequest"></a>

### ListSensorsRequest







<a name="tetragon.ListSensorsResponse"></a>

### ListSensorsResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| sensors | [SensorStatus](#tetragon.SensorStatus) | repeated |  |






<a name="tetragon.ListTracingPoliciesRequest"></a>

### ListTracingPoliciesRequest







<a name="tetragon.ListTracingPoliciesResponse"></a>

### ListTracingPoliciesResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| policies | [TracingPolicyStatus](#tetragon.TracingPolicyStatus) | repeated |  |






<a name="tetragon.RemoveSensorRequest"></a>

### RemoveSensorRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |






<a name="tetragon.RemoveSensorResponse"></a>

### RemoveSensorResponse







<a name="tetragon.SensorStatus"></a>

### SensorStatus



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | name is the name of the sensor |
| enabled | [bool](#bool) |  | enabled marks whether the sensor is enabled |
| collection | [string](#string) |  | collection is the collection the sensor belongs to (typically a tracing policy) |






<a name="tetragon.TracingPolicyStatus"></a>

### TracingPolicyStatus



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [uint64](#uint64) |  | id is the id of the policy |
| name | [string](#string) |  | name is the name of the policy |
| namespace | [string](#string) |  | namespace is the namespace of the policy (or empty of the policy is global) |
| info | [string](#string) |  | info is additional information about the policy |
| sensors | [string](#string) | repeated | sensors loaded in the scope of this policy |
| enabled | [bool](#bool) |  | **Deprecated.** indicating if the policy is enabled. Deprecated: use &#39;state&#39; instead. |
| filter_id | [uint64](#uint64) |  | filter ID of the policy used for k8s filtering |
| error | [string](#string) |  | potential error of the policy |
| state | [TracingPolicyState](#tetragon.TracingPolicyState) |  | current state of the tracing policy |





 


<a name="tetragon.TracingPolicyState"></a>

### TracingPolicyState


| Name | Number | Description |
| ---- | ------ | ----------- |
| TP_STATE_UNKNOWN | 0 | unknown state |
| TP_STATE_ENABLED | 1 | loaded and enabled |
| TP_STATE_DISABLED | 2 | loaded but disabled |
| TP_STATE_LOAD_ERROR | 3 | failed to load |
| TP_STATE_ERROR | 4 | failed during lifetime |


 

 


<a name="tetragon.FineGuidanceSensors"></a>

### FineGuidanceSensors


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| GetEvents | [GetEventsRequest](#tetragon.GetEventsRequest) | [GetEventsResponse](#tetragon.GetEventsResponse) stream |  |
| GetHealth | [GetHealthStatusRequest](#tetragon.GetHealthStatusRequest) | [GetHealthStatusResponse](#tetragon.GetHealthStatusResponse) |  |
| AddTracingPolicy | [AddTracingPolicyRequest](#tetragon.AddTracingPolicyRequest) | [AddTracingPolicyResponse](#tetragon.AddTracingPolicyResponse) |  |
| DeleteTracingPolicy | [DeleteTracingPolicyRequest](#tetragon.DeleteTracingPolicyRequest) | [DeleteTracingPolicyResponse](#tetragon.DeleteTracingPolicyResponse) |  |
| RemoveSensor | [RemoveSensorRequest](#tetragon.RemoveSensorRequest) | [RemoveSensorResponse](#tetragon.RemoveSensorResponse) |  |
| ListTracingPolicies | [ListTracingPoliciesRequest](#tetragon.ListTracingPoliciesRequest) | [ListTracingPoliciesResponse](#tetragon.ListTracingPoliciesResponse) |  |
| EnableTracingPolicy | [EnableTracingPolicyRequest](#tetragon.EnableTracingPolicyRequest) | [EnableTracingPolicyResponse](#tetragon.EnableTracingPolicyResponse) |  |
| DisableTracingPolicy | [DisableTracingPolicyRequest](#tetragon.DisableTracingPolicyRequest) | [DisableTracingPolicyResponse](#tetragon.DisableTracingPolicyResponse) |  |
| ListSensors | [ListSensorsRequest](#tetragon.ListSensorsRequest) | [ListSensorsResponse](#tetragon.ListSensorsResponse) |  |
| EnableSensor | [EnableSensorRequest](#tetragon.EnableSensorRequest) | [EnableSensorResponse](#tetragon.EnableSensorResponse) |  |
| DisableSensor | [DisableSensorRequest](#tetragon.DisableSensorRequest) | [DisableSensorResponse](#tetragon.DisableSensorResponse) |  |
| GetStackTraceTree | [GetStackTraceTreeRequest](#tetragon.GetStackTraceTreeRequest) | [GetStackTraceTreeResponse](#tetragon.GetStackTraceTreeResponse) |  |
| GetVersion | [GetVersionRequest](#tetragon.GetVersionRequest) | [GetVersionResponse](#tetragon.GetVersionResponse) |  |
| RuntimeHook | [RuntimeHookRequest](#tetragon.RuntimeHookRequest) | [RuntimeHookResponse](#tetragon.RuntimeHookResponse) |  |

 



<a name="tetragon/stack.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## tetragon/stack.proto



<a name="tetragon.StackAddress"></a>

### StackAddress



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| address | [uint64](#uint64) |  |  |
| symbol | [string](#string) |  |  |






<a name="tetragon.StackTrace"></a>

### StackTrace



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| addresses | [StackAddress](#tetragon.StackAddress) | repeated |  |






<a name="tetragon.StackTraceLabel"></a>

### StackTraceLabel



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| count | [uint64](#uint64) |  |  |






<a name="tetragon.StackTraceNode"></a>

### StackTraceNode



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| address | [StackAddress](#tetragon.StackAddress) |  |  |
| count | [uint64](#uint64) |  |  |
| labels | [StackTraceLabel](#tetragon.StackTraceLabel) | repeated |  |
| children | [StackTraceNode](#tetragon.StackTraceNode) | repeated |  |





 

 

 

 



<a name="tetragon/tetragon.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## tetragon/tetragon.proto



<a name="tetragon.BinaryProperties"></a>

### BinaryProperties



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| setuid | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  | If set then this is the set user ID used for execution |
| setgid | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  | If set then this is the set group ID used for execution |
| privileges_changed | [ProcessPrivilegesChanged](#tetragon.ProcessPrivilegesChanged) | repeated | The reasons why this binary execution changed privileges. Usually this happens when the process executes a binary with the set-user-ID to root or file capability sets. The final granted privileges can be listed inside the `process_credentials` or capabilities fields part of of the `process` object. |
| file | [FileProperties](#tetragon.FileProperties) |  | File properties in case the executed binary is: 1. An anonymous shared memory file https://man7.org/linux/man-pages/man7/shm_overview.7.html. 2. An anonymous file obtained with memfd API https://man7.org/linux/man-pages/man2/memfd_create.2.html. 3. Or it was deleted from the file system. |






<a name="tetragon.Capabilities"></a>

### Capabilities



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| permitted | [CapabilitiesType](#tetragon.CapabilitiesType) | repeated | Permitted set indicates what capabilities the process can use. This is a limiting superset for the effective capabilities that the thread may assume. It is also a limiting superset for the capabilities that may be added to the inheritable set by a thread without the CAP_SETPCAP in its effective set. |
| effective | [CapabilitiesType](#tetragon.CapabilitiesType) | repeated | Effective set indicates what capabilities are active in a process. This is the set used by the kernel to perform permission checks for the thread. |
| inheritable | [CapabilitiesType](#tetragon.CapabilitiesType) | repeated | Inheritable set indicates which capabilities will be inherited by the current process when running as a root user. |






<a name="tetragon.Container"></a>

### Container



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | Identifier of the container. |
| name | [string](#string) |  | Name of the container. |
| image | [Image](#tetragon.Image) |  | Image of the container. |
| start_time | [google.protobuf.Timestamp](#google.protobuf.Timestamp) |  | Start time of the container. |
| pid | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  | Process identifier in the container namespace. |
| maybe_exec_probe | [bool](#bool) |  | If this is set true, it means that the process might have been originated from a Kubernetes exec probe. For this field to be true, the following must be true: 1. The binary field matches the first element of the exec command list for either liveness or readiness probe excluding the basename. For example, &#34;/bin/ls&#34; and &#34;ls&#34; are considered a match. 2. The arguments field exactly matches the rest of the exec command list. |






<a name="tetragon.CreateContainer"></a>

### CreateContainer
CreateContainer informs the agent that a container was created
This is intented to be used by OCI hooks (but not limited to them) and corresponds to the
CreateContainer hook:
https://github.com/opencontainers/runtime-spec/blob/main/config.md#createcontainer-hooks.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cgroupsPath | [string](#string) |  | cgroupsPath is the cgroups path for the container. The path is expected to be relative to the cgroups mountpoint. See: https://github.com/opencontainers/runtime-spec/blob/58ec43f9fc39e0db229b653ae98295bfde74aeab/specs-go/config.go#L174 |
| rootDir | [string](#string) |  | rootDir is the absolute path of the root directory of the container. See: https://github.com/opencontainers/runtime-spec/blob/main/specs-go/config.go#L174 |
| annotations | [CreateContainer.AnnotationsEntry](#tetragon.CreateContainer.AnnotationsEntry) | repeated | annotations are the run-time annotations for the container see https://github.com/opencontainers/runtime-spec/blob/main/config.md#annotations |






<a name="tetragon.CreateContainer.AnnotationsEntry"></a>

### CreateContainer.AnnotationsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [string](#string) |  |  |






<a name="tetragon.FileProperties"></a>

### FileProperties



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| inode | [InodeProperties](#tetragon.InodeProperties) |  | Inode of the file |
| path | [string](#string) |  | Path of the file |






<a name="tetragon.GetHealthStatusRequest"></a>

### GetHealthStatusRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| event_set | [HealthStatusType](#tetragon.HealthStatusType) | repeated |  |






<a name="tetragon.GetHealthStatusResponse"></a>

### GetHealthStatusResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| health_status | [HealthStatus](#tetragon.HealthStatus) | repeated |  |






<a name="tetragon.HealthStatus"></a>

### HealthStatus



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| event | [HealthStatusType](#tetragon.HealthStatusType) |  |  |
| status | [HealthStatusResult](#tetragon.HealthStatusResult) |  |  |
| details | [string](#string) |  |  |






<a name="tetragon.Image"></a>

### Image



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | Identifier of the container image composed of the registry path and the sha256. |
| name | [string](#string) |  | Name of the container image composed of the registry path and the tag. |






<a name="tetragon.InodeProperties"></a>

### InodeProperties



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| number | [uint64](#uint64) |  | The inode number |
| links | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  | The inode links on the file system. If zero means the file is only in memory |






<a name="tetragon.KernelModule"></a>

### KernelModule



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | Kernel module name |
| signature_ok | [google.protobuf.BoolValue](#google.protobuf.BoolValue) |  | If true the module signature was verified successfully. Depends on kernels compiled with CONFIG_MODULE_SIG option, for details please read: https://www.kernel.org/doc/Documentation/admin-guide/module-signing.rst |
| tainted | [TaintedBitsType](#tetragon.TaintedBitsType) | repeated | The module tainted flags that will be applied on the kernel. For further details please read: https://docs.kernel.org/admin-guide/tainted-kernels.html |






<a name="tetragon.KprobeArgument"></a>

### KprobeArgument



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| string_arg | [string](#string) |  |  |
| int_arg | [int32](#int32) |  |  |
| skb_arg | [KprobeSkb](#tetragon.KprobeSkb) |  |  |
| size_arg | [uint64](#uint64) |  |  |
| bytes_arg | [bytes](#bytes) |  |  |
| path_arg | [KprobePath](#tetragon.KprobePath) |  |  |
| file_arg | [KprobeFile](#tetragon.KprobeFile) |  |  |
| truncated_bytes_arg | [KprobeTruncatedBytes](#tetragon.KprobeTruncatedBytes) |  |  |
| sock_arg | [KprobeSock](#tetragon.KprobeSock) |  |  |
| cred_arg | [KprobeCred](#tetragon.KprobeCred) |  |  |
| long_arg | [int64](#int64) |  |  |
| bpf_attr_arg | [KprobeBpfAttr](#tetragon.KprobeBpfAttr) |  |  |
| perf_event_arg | [KprobePerfEvent](#tetragon.KprobePerfEvent) |  |  |
| bpf_map_arg | [KprobeBpfMap](#tetragon.KprobeBpfMap) |  |  |
| uint_arg | [uint32](#uint32) |  |  |
| user_namespace_arg | [KprobeUserNamespace](#tetragon.KprobeUserNamespace) |  | **Deprecated.**  |
| capability_arg | [KprobeCapability](#tetragon.KprobeCapability) |  |  |
| process_credentials_arg | [ProcessCredentials](#tetragon.ProcessCredentials) |  |  |
| user_ns_arg | [UserNamespace](#tetragon.UserNamespace) |  |  |
| module_arg | [KernelModule](#tetragon.KernelModule) |  |  |
| kernel_cap_t_arg | [string](#string) |  | Capabilities in hexadecimal format. |
| cap_inheritable_arg | [string](#string) |  | Capabilities inherited by a forked process in hexadecimal format. |
| cap_permitted_arg | [string](#string) |  | Capabilities that are currently permitted in hexadecimal format. |
| cap_effective_arg | [string](#string) |  | Capabilities that are actually used in hexadecimal format. |
| linux_binprm_arg | [KprobeLinuxBinprm](#tetragon.KprobeLinuxBinprm) |  |  |
| label | [string](#string) |  |  |






<a name="tetragon.KprobeBpfAttr"></a>

### KprobeBpfAttr



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| ProgType | [string](#string) |  |  |
| InsnCnt | [uint32](#uint32) |  |  |
| ProgName | [string](#string) |  |  |






<a name="tetragon.KprobeBpfMap"></a>

### KprobeBpfMap



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| MapType | [string](#string) |  |  |
| KeySize | [uint32](#uint32) |  |  |
| ValueSize | [uint32](#uint32) |  |  |
| MaxEntries | [uint32](#uint32) |  |  |
| MapName | [string](#string) |  |  |






<a name="tetragon.KprobeCapability"></a>

### KprobeCapability



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| value | [google.protobuf.Int32Value](#google.protobuf.Int32Value) |  |  |
| name | [string](#string) |  |  |






<a name="tetragon.KprobeCred"></a>

### KprobeCred



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| permitted | [CapabilitiesType](#tetragon.CapabilitiesType) | repeated |  |
| effective | [CapabilitiesType](#tetragon.CapabilitiesType) | repeated |  |
| inheritable | [CapabilitiesType](#tetragon.CapabilitiesType) | repeated |  |






<a name="tetragon.KprobeFile"></a>

### KprobeFile



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| mount | [string](#string) |  |  |
| path | [string](#string) |  |  |
| flags | [string](#string) |  |  |






<a name="tetragon.KprobeLinuxBinprm"></a>

### KprobeLinuxBinprm



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| path | [string](#string) |  |  |






<a name="tetragon.KprobePath"></a>

### KprobePath



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| mount | [string](#string) |  |  |
| path | [string](#string) |  |  |
| flags | [string](#string) |  |  |






<a name="tetragon.KprobePerfEvent"></a>

### KprobePerfEvent



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| KprobeFunc | [string](#string) |  |  |
| Type | [string](#string) |  |  |
| Config | [uint64](#uint64) |  |  |
| ProbeOffset | [uint64](#uint64) |  |  |






<a name="tetragon.KprobeSkb"></a>

### KprobeSkb



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| hash | [uint32](#uint32) |  |  |
| len | [uint32](#uint32) |  |  |
| priority | [uint32](#uint32) |  |  |
| mark | [uint32](#uint32) |  |  |
| saddr | [string](#string) |  |  |
| daddr | [string](#string) |  |  |
| sport | [uint32](#uint32) |  |  |
| dport | [uint32](#uint32) |  |  |
| proto | [uint32](#uint32) |  |  |
| sec_path_len | [uint32](#uint32) |  |  |
| sec_path_olen | [uint32](#uint32) |  |  |
| protocol | [string](#string) |  |  |
| family | [string](#string) |  |  |






<a name="tetragon.KprobeSock"></a>

### KprobeSock



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| family | [string](#string) |  |  |
| type | [string](#string) |  |  |
| protocol | [string](#string) |  |  |
| mark | [uint32](#uint32) |  |  |
| priority | [uint32](#uint32) |  |  |
| saddr | [string](#string) |  |  |
| daddr | [string](#string) |  |  |
| sport | [uint32](#uint32) |  |  |
| dport | [uint32](#uint32) |  |  |
| cookie | [uint64](#uint64) |  |  |
| state | [string](#string) |  |  |






<a name="tetragon.KprobeTruncatedBytes"></a>

### KprobeTruncatedBytes



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bytes_arg | [bytes](#bytes) |  |  |
| orig_size | [uint64](#uint64) |  |  |






<a name="tetragon.KprobeUserNamespace"></a>

### KprobeUserNamespace



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| level | [google.protobuf.Int32Value](#google.protobuf.Int32Value) |  |  |
| owner | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| group | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| ns | [Namespace](#tetragon.Namespace) |  |  |






<a name="tetragon.Namespace"></a>

### Namespace



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| inum | [uint32](#uint32) |  | Inode number of the namespace. |
| is_host | [bool](#bool) |  | Indicates if namespace belongs to host. |






<a name="tetragon.Namespaces"></a>

### Namespaces



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| uts | [Namespace](#tetragon.Namespace) |  | Hostname and NIS domain name. |
| ipc | [Namespace](#tetragon.Namespace) |  | System V IPC, POSIX message queues. |
| mnt | [Namespace](#tetragon.Namespace) |  | Mount points. |
| pid | [Namespace](#tetragon.Namespace) |  | Process IDs. |
| pid_for_children | [Namespace](#tetragon.Namespace) |  | Process IDs for children processes. |
| net | [Namespace](#tetragon.Namespace) |  | Network devices, stacks, ports, etc. |
| time | [Namespace](#tetragon.Namespace) |  | Boot and monotonic clocks. |
| time_for_children | [Namespace](#tetragon.Namespace) |  | Boot and monotonic clocks for children processes. |
| cgroup | [Namespace](#tetragon.Namespace) |  | Cgroup root directory. |
| user | [Namespace](#tetragon.Namespace) |  | User and group IDs. |






<a name="tetragon.Pod"></a>

### Pod



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| namespace | [string](#string) |  | Kubernetes namespace of the Pod. |
| name | [string](#string) |  | Name of the Pod. |
| container | [Container](#tetragon.Container) |  | Container of the Pod from which the process that triggered the event originates. |
| pod_labels | [Pod.PodLabelsEntry](#tetragon.Pod.PodLabelsEntry) | repeated | Contains all the labels of the pod. |
| workload | [string](#string) |  | Kubernetes workload of the Pod. |
| workload_kind | [string](#string) |  | Kubernetes workload kind (e.g. &#34;Deployment&#34;, &#34;DaemonSet&#34;) of the Pod. |






<a name="tetragon.Pod.PodLabelsEntry"></a>

### Pod.PodLabelsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [string](#string) |  |  |






<a name="tetragon.Process"></a>

### Process



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| exec_id | [string](#string) |  | Exec ID uniquely identifies the process over time across all the nodes in the cluster. |
| pid | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  | Process identifier from host PID namespace. |
| uid | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  | User identifier associated with the process. |
| cwd | [string](#string) |  | Current working directory of the process. |
| binary | [string](#string) |  | Absolute path of the executed binary. |
| arguments | [string](#string) |  | Arguments passed to the binary at execution. |
| flags | [string](#string) |  | Flags are for debugging purposes only and should not be considered a reliable source of information. They hold various information about which syscalls generated events, use of internal Tetragon buffers, errors and more. - `execve` This event is generated by an execve syscall for a new process. See procFs for the other option. A correctly formatted event should either set execve or procFS (described next). - `procFS` This event is generated from a proc interface. This happens at Tetragon init when existing processes are being loaded into Tetragon event buffer. All events should have either execve or procFS set. - `truncFilename` Indicates a truncated processes filename because the buffer size is too small to contain the process filename. Consider increasing buffer size to avoid this. - `truncArgs` Indicates truncated the processes arguments because the buffer size was too small to contain all exec args. Consider increasing buffer size to avoid this. - `taskWalk` Primarily useful for debugging. Indicates a walked process hierarchy to find a parent process in the Tetragon buffer. This may happen when we did not receive an exec event for the immediate parent of a process. Typically means we are looking at a fork that in turn did another fork we don&#39;t currently track fork events exactly and instead push an event with the original parent exec data. This flag can provide this insight into the event if needed. - `miss` An error flag indicating we could not find parent info in the Tetragon event buffer. If this is set it should be reported to Tetragon developers for debugging. Tetragon will do its best to recover information about the process from available kernel data structures instead of using cached info in this case. However, args will not be available. - `needsAUID` An internal flag for Tetragon to indicate the audit has not yet been resolved. The BPF hooks look at this flag to determine if probing the audit system is necessary. - `errorFilename` An error flag indicating an error happened while reading the filename. If this is set it should be reported to Tetragon developers for debugging. - `errorArgs` An error flag indicating an error happened while reading the process args. If this is set it should be reported to Tetragon developers for debugging - `needsCWD` An internal flag for Tetragon to indicate the current working directory has not yet been resolved. The Tetragon hooks look at this flag to determine if probing the CWD is necessary. - `noCWDSupport` Indicates that CWD is removed from the event because the buffer size is too small. Consider increasing buffer size to avoid this. - `rootCWD` Indicates that CWD is the root directory. This is necessary to inform readers the CWD is not in the event buffer and is &#39;/&#39; instead. - `errorCWD` An error flag indicating an error occurred while reading the CWD of a process. If this is set it should be reported to Tetragon developers for debugging. - `clone` Indicates the process issued a clone before exec*. This is the general flow to exec* a new process, however its possible to replace the current process with a new process by doing an exec* without a clone. In this case the flag will be omitted and the same PID will be used by the kernel for both the old process and the newly exec&#39;d process. |
| start_time | [google.protobuf.Timestamp](#google.protobuf.Timestamp) |  | Start time of the execution. |
| auid | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  | Audit user ID, this ID is assigned to a user upon login and is inherited by every process even when the user&#39;s identity changes. For example, by switching user accounts with su - john. |
| pod | [Pod](#tetragon.Pod) |  | Information about the the Kubernetes Pod where the event originated. |
| docker | [string](#string) |  | The 15 first digits of the container ID. |
| parent_exec_id | [string](#string) |  | Exec ID of the parent process. |
| refcnt | [uint32](#uint32) |  | Reference counter from the Tetragon process cache. |
| cap | [Capabilities](#tetragon.Capabilities) |  | Set of capabilities that define the permissions the process can execute with. |
| ns | [Namespaces](#tetragon.Namespaces) |  | Linux namespaces of the process, disabled by default, can be enabled by the `--enable-process-ns` flag. |
| tid | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  | Thread ID, note that for the thread group leader, tid is equal to pid. |
| process_credentials | [ProcessCredentials](#tetragon.ProcessCredentials) |  | Process credentials |
| binary_properties | [BinaryProperties](#tetragon.BinaryProperties) |  | Executed binary properties. This field is only available on ProcessExec events. |






<a name="tetragon.ProcessCredentials"></a>

### ProcessCredentials



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| uid | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  | The real user ID |
| gid | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  | The real group ID |
| euid | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  | The effective user ID |
| egid | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  | The effective group ID |
| suid | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  | The saved user ID |
| sgid | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  | The saved group ID |
| fsuid | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  | the filesystem user ID |
| fsgid | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  | The filesystem group ID |
| securebits | [SecureBitsType](#tetragon.SecureBitsType) | repeated | Secure management flags |
| caps | [Capabilities](#tetragon.Capabilities) |  | Set of capabilities that define the permissions the process can execute with. |
| user_ns | [UserNamespace](#tetragon.UserNamespace) |  | User namespace where the UIDs, GIDs and capabilities are relative to. |






<a name="tetragon.ProcessExec"></a>

### ProcessExec



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  | Process that triggered the exec. |
| parent | [Process](#tetragon.Process) |  | Immediate parent of the process. |
| ancestors | [Process](#tetragon.Process) | repeated | Ancestors of the process beyond the immediate parent. |






<a name="tetragon.ProcessExit"></a>

### ProcessExit



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  | Process that triggered the exit. |
| parent | [Process](#tetragon.Process) |  | Immediate parent of the process. |
| signal | [string](#string) |  | Signal that the process received when it exited, for example SIGKILL or SIGTERM (list all signal names with `kill -l`). If there is no signal handler implemented for a specific process, we report the exit status code that can be found in the status field. |
| status | [uint32](#uint32) |  | Status code on process exit. For example, the status code can indicate if an error was encountered or the program exited successfully. |
| time | [google.protobuf.Timestamp](#google.protobuf.Timestamp) |  | Date and time of the event. |






<a name="tetragon.ProcessKprobe"></a>

### ProcessKprobe



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  | Process that triggered the kprobe. |
| parent | [Process](#tetragon.Process) |  | Immediate parent of the process. |
| function_name | [string](#string) |  | Symbol on which the kprobe was attached. |
| args | [KprobeArgument](#tetragon.KprobeArgument) | repeated | Arguments definition of the observed kprobe. |
| return | [KprobeArgument](#tetragon.KprobeArgument) |  | Return value definition of the observed kprobe. |
| action | [KprobeAction](#tetragon.KprobeAction) |  | Action performed when the kprobe matched. |
| stack_trace | [StackTraceEntry](#tetragon.StackTraceEntry) | repeated | Kernel stack trace to the call. |
| policy_name | [string](#string) |  | Name of the Tracing Policy that created that kprobe. |
| return_action | [KprobeAction](#tetragon.KprobeAction) |  | Action performed when the return kprobe executed. |
| message | [string](#string) |  | Short message of the Tracing Policy to inform users what is going on. |






<a name="tetragon.ProcessLoader"></a>

### ProcessLoader
loader sensor event triggered for loaded binary/library


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  |  |
| path | [string](#string) |  |  |
| buildid | [bytes](#bytes) |  |  |






<a name="tetragon.ProcessTracepoint"></a>

### ProcessTracepoint



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  | Process that triggered the tracepoint. |
| parent | [Process](#tetragon.Process) |  | Immediate parent of the process. |
| subsys | [string](#string) |  | Subsystem of the tracepoint. |
| event | [string](#string) |  | Event of the subsystem. |
| args | [KprobeArgument](#tetragon.KprobeArgument) | repeated | Arguments definition of the observed tracepoint. TODO: once we implement all we want, rename KprobeArgument to GenericArgument |
| policy_name | [string](#string) |  | Name of the policy that created that tracepoint. |
| action | [KprobeAction](#tetragon.KprobeAction) |  | Action performed when the tracepoint matched. |
| message | [string](#string) |  | Short message of the Tracing Policy to inform users what is going on. |






<a name="tetragon.ProcessUprobe"></a>

### ProcessUprobe



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#tetragon.Process) |  |  |
| parent | [Process](#tetragon.Process) |  |  |
| path | [string](#string) |  |  |
| symbol | [string](#string) |  |  |
| policy_name | [string](#string) |  | Name of the policy that created that uprobe. |
| message | [string](#string) |  | Short message of the Tracing Policy to inform users what is going on. |
| args | [KprobeArgument](#tetragon.KprobeArgument) | repeated | Arguments definition of the observed uprobe. |






<a name="tetragon.RuntimeHookRequest"></a>

### RuntimeHookRequest
RuntimeHookRequest synchronously propagates information to the agent about run-time state.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| createContainer | [CreateContainer](#tetragon.CreateContainer) |  |  |






<a name="tetragon.RuntimeHookResponse"></a>

### RuntimeHookResponse







<a name="tetragon.StackTraceEntry"></a>

### StackTraceEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| address | [uint64](#uint64) |  | address is the kernel function address. |
| offset | [uint64](#uint64) |  | offset is the offset into the native instructions for the function. |
| symbol | [string](#string) |  | symbol is the symbol name of the function. |






<a name="tetragon.Test"></a>

### Test



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| arg0 | [uint64](#uint64) |  |  |
| arg1 | [uint64](#uint64) |  |  |
| arg2 | [uint64](#uint64) |  |  |
| arg3 | [uint64](#uint64) |  |  |






<a name="tetragon.UserNamespace"></a>

### UserNamespace



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| level | [google.protobuf.Int32Value](#google.protobuf.Int32Value) |  | Nested level of the user namespace. Init or host user namespace is at level 0. |
| uid | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  | The owner user ID of the namespace |
| gid | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  | The owner group ID of the namepace. |
| ns | [Namespace](#tetragon.Namespace) |  | The user namespace details that include the inode number of the namespace. |





 


<a name="tetragon.HealthStatusResult"></a>

### HealthStatusResult


| Name | Number | Description |
| ---- | ------ | ----------- |
| HEALTH_STATUS_UNDEF | 0 |  |
| HEALTH_STATUS_RUNNING | 1 |  |
| HEALTH_STATUS_STOPPED | 2 |  |
| HEALTH_STATUS_ERROR | 3 |  |



<a name="tetragon.HealthStatusType"></a>

### HealthStatusType


| Name | Number | Description |
| ---- | ------ | ----------- |
| HEALTH_STATUS_TYPE_UNDEF | 0 |  |
| HEALTH_STATUS_TYPE_STATUS | 1 |  |



<a name="tetragon.KprobeAction"></a>

### KprobeAction


| Name | Number | Description |
| ---- | ------ | ----------- |
| KPROBE_ACTION_UNKNOWN | 0 | Unknown action |
| KPROBE_ACTION_POST | 1 | Post action creates an event (default action). |
| KPROBE_ACTION_FOLLOWFD | 2 | Post action creates a mapping between file descriptors and file names. |
| KPROBE_ACTION_SIGKILL | 3 | Sigkill action synchronously terminates the process. |
| KPROBE_ACTION_UNFOLLOWFD | 4 | Post action removes a mapping between file descriptors and file names. |
| KPROBE_ACTION_OVERRIDE | 5 | Override action modifies the return value of the call. |
| KPROBE_ACTION_COPYFD | 6 | Post action dupplicates a mapping between file descriptors and file names. |
| KPROBE_ACTION_GETURL | 7 | GetURL action issue an HTTP Get request against an URL from userspace. |
| KPROBE_ACTION_DNSLOOKUP | 8 | GetURL action issue a DNS lookup against an URL from userspace. |
| KPROBE_ACTION_NOPOST | 9 | NoPost action suppresses the transmission of the event to userspace. |
| KPROBE_ACTION_SIGNAL | 10 | Signal action sends specified signal to the process. |
| KPROBE_ACTION_TRACKSOCK | 11 | TrackSock action tracks socket. |
| KPROBE_ACTION_UNTRACKSOCK | 12 | UntrackSock action un-tracks socket. |
| KPROBE_ACTION_NOTIFYENFORCER | 13 | NotifyEnforcer action notifies killer sensor. |



<a name="tetragon.TaintedBitsType"></a>

### TaintedBitsType
Tainted bits to indicate if the kernel was tainted. For further details: https://docs.kernel.org/admin-guide/tainted-kernels.html

| Name | Number | Description |
| ---- | ------ | ----------- |
| TAINT_UNSET | 0 |  |
| TAINT_PROPRIETARY_MODULE | 1 | A proprietary module was loaded. |
| TAINT_FORCED_MODULE | 2 | A module was force loaded. |
| TAINT_FORCED_UNLOAD_MODULE | 4 | A module was force unloaded. |
| TAINT_STAGED_MODULE | 1024 | A staging driver was loaded. |
| TAINT_OUT_OF_TREE_MODULE | 4096 | An out of tree module was loaded. |
| TAINT_UNSIGNED_MODULE | 8192 | An unsigned module was loaded. Supported only on kernels built with CONFIG_MODULE_SIG option. |
| TAINT_KERNEL_LIVE_PATCH_MODULE | 32768 | The kernel has been live patched. |
| TAINT_TEST_MODULE | 262144 | Loading a test module. |


 

 

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

