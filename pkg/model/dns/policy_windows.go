package dns

import (
	"bytes"
	"io"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

func SanitizeWindowsPath(path string) string {
	if len(path) < 4 {
		return path
	}

	// Prepend a \\??\\ to the path if it does not already exist
	if path[0:4] != "\\??\\" {
		path = "\\??\\" + path
	}

	// convert to Utf-16
	encoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()

	// Transform the UTF-8 string to UTF-16
	utf16Bytes, err := io.ReadAll(transform.NewReader(bytes.NewReader([]byte(path)), encoder))
	if err != nil {
		return ""
	}

	return string(utf16Bytes)
}

func (state *PolicyState) AddSrcPolicy(src *types.ProcessTreeKey, policy *types.TetragonNetworkPolicy, init bool) ([]*record.DatapathRecord, error) {
	records := []*record.DatapathRecord{}

	dfltAction, err := calculateAction(&policy.Default)
	if err != nil {
		logger.GetLogger().Error("policy has unsupported or invalid default action", logfields.Error, err,
			"uid", policy.PolicyUID, "action", policy.Action)
		return records, err
	}

	action, err := calculateAction(&policy.Action)
	if err != nil {
		logger.GetLogger().Error("policy has unsupported or invalid action", logfields.Error, err,
			"uid", policy.PolicyUID, "action", policy.Action)
		return records, err
	}

	// Records are mapped to the datapath. We need a distinct record
	// for each process or lack of processSelector simply apply to
	// the entire pod.
	if len(policy.Subject.InProcessName) > 0 {
		for _, process := range policy.Subject.InProcessName {
			process = SanitizeWindowsPath(process)
			self, err := prog.GetBinaryId(process, true)
			if err != nil {
				logger.GetLogger().Warn("Failed to create record", logfields.Error, err, "uid", policy.PolicyUID, "process", process)
				return records, err
			}

			processSrc := &types.ProcessTreeKey{
				NSID:  src.NSID,
				Depth: 0,
				Self:  self,
				Path:  [8]uint64{0, 0, 0, 0, 0, 0, 0, 0},
			}

			r := state.policyDestRecords(processSrc, action, policy, init)
			records = append(records, r...)
		}
	} else {
		r := state.policyDestRecords(src, action, policy, init)
		records = append(records, r...)
	}

	// Append the default record for the Pod layer
	endpoint := record.DatapathEndpoint{
		EP:   nil,
		Port: 0,
	}
	dfltRecord := &record.DatapathRecord{
		PolicyUID: policy.PolicyUID,
		Src:       src,
		Endpoint:  endpoint,
		Action:    dfltAction,
		Init:      init,
	}
	records = append(records, dfltRecord)

	return records, nil
}
