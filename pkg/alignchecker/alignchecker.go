package alignchecker

import (
	"github.com/cilium/tetragon/pkg/alignchecker"

	"github.com/isovalent/hubble-fgs/pkg/api/dnsapi"
	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	"github.com/isovalent/hubble-fgs/pkg/api/httpapi"
	"github.com/isovalent/hubble-fgs/pkg/api/modelapi"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/tlsapi"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	fm "github.com/isovalent/hubble-fgs/pkg/sensors/file/utils"
)

// CheckStructAlignments checks whether size and offsets of the C and Go

// structs for the datapath match.
//
// C struct size info is extracted from the given ELF object file debug section
// encoded in DWARF.
//
// To find a matching C struct field, a Go field has to be tagged with
// `align:"field_name_in_c_struct". In the case of unnamed union field, such
// union fields can be referred with special tags - `align:"$union0"`,
// `align:"$union1"`, etc.
func CheckStructAlignments(pathToObj string) error {
	alignments := map[string][]any{
		// Layer 3
		"cfg_value":                 {networkapi.Layer3ConfigValue{}},
		"tcp_send_check_sample_cfg": {networkapi.TCPSockStatValue{}},
		"tcp_event_disable_config":  {networkapi.TCPEventDisableValue{}},
		"udp_sensor_config":         {networkapi.UdpConfigValue{}},
		"cgroup_dispatch_cfg":       {networkapi.CgroupProtocolConfigValue{}},
		"msg_ip_tuple":              {networkapi.MsgIPTuple{}},
		"msg_ip_event":              {networkapi.MsgIPEvent{}},
		"msg_ip_with_tnp_event":     {networkapi.MsgIPWithTNPEvent{}},
		"msg_ip_with_stats_event":   {networkapi.MsgIPWithStatsEvent{}},
		"tcpsocketmap_value":        {networkapi.TcpValue{}},
		"udp_info_key":              {networkapi.UdpInfoKey{}},
		"udp_info_value":            {networkapi.UdpInfoValue{}},
		"msg_socket_stats":          {networkapi.MsgSocketStats{}},

		// Layer 7
		"__msg_http_event":   {httpapi.MsgHttpEvent{}},
		"__msg_http":         {httpapi.MsgHttp{}},
		"msg_tls_event":      {tlsapi.MsgTLSEvent{}},
		"msg_tls":            {tlsapi.MsgTLS{}},
		"__http_state_stats": {httpapi.HttpStateStats{}},
		"ip_addr":            {dnsapi.IPAddr{}},

		// FIM
		"inode_key":           {fileapi.InodeKey{}},
		"inode_val":           {fileapi.InodeVal{}},
		"msg_file_path":       {fileapi.MsgFilePath{}},
		"msg_fs_info":         {fileapi.MsgFsInfo{}},
		"msg_file_ops":        {fileapi.MsgFileEvent{}},
		"msg_file_split_path": {fileapi.MsgFileSplitPath{}},
		"msg_rename_elem":     {fileapi.MsgRenameElem{}},
		"msg_file_rename_ops": {fileapi.MsgFileRenameEvent{}},
		"lpm_key":             {fileapi.LPMMapKey{}},
		"lpm_val":             {fileapi.LPMMapValue{}},
		"digest_key":          {fileapi.DigestKey{}},
		"file_exec_stats":     {fileapi.FileExecStats{}},
		"file_sel_caps":       {fileapi.SelCaps{}},
		"file_sel_namespaces": {fileapi.SelNs{}},
		"file_errors":         {fileapi.FileErrors{}},
		"pattern_val":         {fileapi.PatternValue{}},
		"full_path":           {fileapi.FullPath{}},
		"glob_state":          {fm.GlobState{}},

		"fd_lookup_config": {networkapi.FdLookupValue{}},

		// App model
		"msg_execve_key":              {types.ProcessExecveKey{}},
		"process_tree_value":          {types.ProcessTreeValue{}},
		"process_tree_key":            {types.ProcessTreeKey{}},
		"destination_endpoint_key":    {types.DestinationEndpointKey{}},
		"destination_endpoint_value":  {types.DestinationEndpointValue{}},
		"listen_endpoint_key":         {types.ListenKey{}},
		"listen_endpoint_value":       {types.ListenValue{}},
		"endpoint_id_key":             {types.EndpointIdKey{}},
		"endpoint_id_value":           {types.EndpointIdValue{}},
		"process_tree_binary_uid_key": {types.ProcessTreeBinaryUUIDValue{}},
		"tree_id":                     {types.TreeId{}},
		"process_syscall_value":       {types.ProcessSyscallValue{}},
		"procfs_cfg":                  {modelapi.ProcFSConfigValue{}},
		"u32":                         {modelapi.ProcFSConfigKey{}},
	}

	return alignchecker.CheckStructAlignments(pathToObj, alignments, true)
}
