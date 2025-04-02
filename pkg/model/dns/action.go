package dns

import (
	"fmt"
	"strconv"

	"github.com/cilium/tetragon/pkg/logger"
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
			logger.GetLogger().WithError(err).Warn("failed to conver reset time")
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
		Quota: quota,
		Reset: reset,
		Deny:  deny,
	}, nil
}
