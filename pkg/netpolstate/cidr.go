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

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

func addDestSrcCIDRRecords(
	policy types.TetragonPolicyUniqueID,
	dest *types.TetragonNetworkDestination,
	src *types.ProcessTreeKey,
	action *record.DatapathAction,
	init bool,
) ([]record.DatapathRecord, error) {
	ep := &endpoint.Endpoint{
		Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
		CIDR: dest.CIDR,
	}

	if len(dest.Ports) == 0 {
		endpoint := record.DatapathEndpoint{
			EP:   ep,
			Port: 0,
		}
		return []record.DatapathRecord{
			{
				PolicyUID: policy,
				Src:       src,
				Endpoint:  endpoint,
				Action:    action,
				Init:      init,
			},
		}, nil
	}

	records := []record.DatapathRecord{}
	for _, port := range dest.Ports {
		endpoint := record.DatapathEndpoint{
			EP:   ep,
			Port: port,
		}
		records = append(records, record.DatapathRecord{
			PolicyUID: policy,
			Src:       src,
			Endpoint:  endpoint,
			Action:    action,
			Init:      init,
		})
	}
	return records, nil
}

func addDestCIDRRecords(
	policy types.TetragonPolicyUniqueID,
	dest *types.TetragonNetworkDestination,
	subject *types.TetragonNetworkSubject,
	podSubject *types.ProcessTreeKey,
	action *record.DatapathAction,
) ([]record.DatapathRecord, error) {
	state := GetRealizedState()
	records := []record.DatapathRecord{}

	for _, process := range subject.InProcessName {
		self, err := state.prog.GetBinaryId(process, true) // CIDR policies do not include args for now
		if err != nil {
			logger.GetLogger().Warn("add cidr binary id error", logfields.Error, err)
			continue
		}
		processSrc := &types.ProcessTreeKey{
			NSID:  podSubject.NSID,
			Depth: 0,
			Self:  self,
			Path:  [8]uint64{0, 0, 0, 0, 0, 0, 0, 0},
		}
		r, err := addDestSrcCIDRRecords(policy, dest, processSrc, action, true)
		if err != nil {
			logger.GetLogger().Warn("add DestCIDR recrods failed", logfields.Error, err)
		} else {
			records = append(records, r...)
		}
	}

	if len(subject.InProcessName) == 0 {
		r, err := addDestSrcCIDRRecords(policy, dest, podSubject, action, true)
		if err != nil {
			logger.GetLogger().Warn("add DestCIDR recrods failed", logfields.Error, err)
		} else {
			records = append(records, r...)
		}
	}

	return records, nil

}
