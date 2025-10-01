package dns

import (
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

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

	r := state.policyDestRecords(src, action, policy, init)
	records = append(records, r...)

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
