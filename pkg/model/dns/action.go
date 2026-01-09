// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dns

import (
	"fmt"
	"strconv"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

func quotaToNs(reset string) (uint64, error) {
	var mult uint64

	specifier := reset[len(reset)-1:]
	switch specifier {
	case "m":
		mult = 60000000000
	case "h":
		mult = 3600000000000
	case "s":
		mult = 1000000000
	default:
		return 0, fmt.Errorf("unknown reset specifier %s", specifier)
	}
	time := reset[0 : len(reset)-1]
	resetNS, err := strconv.ParseUint(time, 10, 64)
	if err != nil {
		return 0, err
	}
	resetNS *= mult
	return resetNS, nil
}

func calculateAction(a *types.TetragonNetworkAction) (*record.DatapathAction, error) {
	var err error
	quota := uint64(0)
	reset := uint64(0)

	if a.QuotaAction != nil {
		reset, err = quotaToNs(a.QuotaAction.Reset)
		if err != nil {
			logger.GetLogger().Warn("failed to conver reset time", logfields.Error, err)
			return nil, err
		}

		quota, err = strconv.ParseUint(a.QuotaAction.Quota, 10, 64)
		if err != nil {
			return nil, err
		}
	}

	deny := record.PolicyNone
	if a.EnforceAction != nil {
		if a.EnforceAction.Deny {
			deny |= record.PolicyDeny
		}
		if a.EnforceAction.Allow {
			deny |= record.PolicyAllow
		}
	}

	return &record.DatapathAction{
		QuotaLimit: quota,
		ResetTime:  reset,
		Action:     deny,
	}, nil
}
