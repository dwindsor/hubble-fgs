package alignchecker

import (
	"github.com/cilium/cilium/pkg/alignchecker"
	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	"github.com/isovalent/hubble-fgs/pkg/api/httpapi"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/tlsapi"
	"github.com/isovalent/hubble-fgs/pkg/sensors/ip"
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
		"msg_ip_event": {networkapi.MsgIPEvent{}},

		// Layer 7
		"__msg_http_event": {httpapi.MsgHttpEvent{}},
		"__msg_http":       {httpapi.MsgHttp{}},
		"msg_tls_event":    {tlsapi.MsgTLSEvent{}},
		"msg_tls":          {tlsapi.MsgTLS{}},

		// FIM
		"hash_map_file_key":   {fileapi.HashMapFileKey{}},
		"hash_map_file_val":   {fileapi.HashMapFileVal{}},
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

		"fd_lookup_config": {ip.FdLookupValue{}},
	}

	return alignchecker.CheckStructAlignments(pathToObj, alignments, true)
}
