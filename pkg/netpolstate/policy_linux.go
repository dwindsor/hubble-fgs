// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package netpolstate

import (
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

func (state *PolicyState) AddSrcPolicy(src *types.ProcessTreeKey, policy *types.TetragonNetworkPolicy, init bool) ([]record.DatapathRecord, error) {
	records := []record.DatapathRecord{}

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
			self, err := state.prog.GetBinaryId(process, true) // DNS policies do not include args for now
			if err != nil {
				logger.GetLogger().Warn("Failed to create record", logfields.Error, err, "uid", policy.PolicyUID, "process", process)
				return records, err
			}

			processSrc := &types.ProcessTreeKey{
				WLID:  src.WLID,
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
	dfltRecord := record.DatapathRecord{
		PolicyUID: policy.PolicyUID,
		Src:       src,
		Endpoint:  endpoint,
		Action:    dfltAction,
		Init:      init,
	}
	records = append(records, dfltRecord)

	return records, nil
}
