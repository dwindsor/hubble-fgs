package alignchecker_test

import (
	"path/filepath"
	"testing"

	"github.com/cilium/cilium/pkg/alignchecker"
	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	"github.com/isovalent/hubble-fgs/pkg/api/httpapi"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/tlsapi"
	"github.com/isovalent/hubble-fgs/pkg/sensors/ip"
	"github.com/stretchr/testify/assert"

	tetragonAlignchecker "github.com/cilium/tetragon/pkg/alignchecker"
)

func Test_EnterpriseAlignments(t *testing.T) {
	bpfObjPath := filepath.Join(tetragonLib, "bpf_alignchecker.o")

	entrpriseAligntments := map[string][]any{
		// Layer 3
		"msg_ip_event": {networkapi.MsgIPEvent{}},

		// Layer 7
		// TODO: layer 7 is currently not aligned properly, will fix
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
		"fd_lookup_config":    {ip.FdLookupValue{}},
	}

	err := alignchecker.CheckStructAlignments(bpfObjPath, entrpriseAligntments, true)
	assert.NoError(t, err, "enterprise types must align")
}

func Test_OSSAlignments(t *testing.T) {
	bpfObjPath := filepath.Join(tetragonLib, "bpf_alignchecker_oss.o")
	err := tetragonAlignchecker.CheckStructAlignments(bpfObjPath)
	assert.NoError(t, err, "oss types must align")
}
