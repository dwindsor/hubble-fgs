package dns

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/sirupsen/logrus"
)

func (state *PolicyState) progRemoveCIDRDest(
	cidr *types.TetragonNetworkCIDR,
	src *types.ProcessTreeKey,
) error {
	ep := &endpoint.Endpoint{
		Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
		Ip:   cidr.CIDR,
	}
	endpoint := record.DatapathEndpoint{
		EP:   ep,
		Port: 0,
	}
	record := &record.DatapathRecord{
		Src:      src,
		Endpoint: endpoint,
	}
	if err := prog.RemoveSingleRecord(record); err != nil {
		logger.GetLogger().WithFields(logrus.Fields{
			"cgid": src.NSID,
			"self": src.Self,
			"dest": cidr.CIDR,
		}).WithError(err).Error("TCP CIDR remove Failed")
		return err
	}
	logger.GetLogger().WithFields(logrus.Fields{
		"cgid": src.NSID,
		"self": src.Self,
		"dest": cidr.CIDR,
	}).Debug("TCP CIDR removed")
	return nil
}

func (state *PolicyState) addDestSrcCIDRRecords(
	policy *record.Policy,
	dest *types.TetragonNetworkDestination,
	src *types.ProcessTreeKey,
	action *record.DatapathAction,
	init bool,
) ([]*record.DatapathRecord, error) {
	ep := &endpoint.Endpoint{
		Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
		Ip:   dest.CIDR.CIDR,
	}

	if len(dest.Ports) == 0 {
		endpoint := record.DatapathEndpoint{
			EP:   ep,
			Port: 0,
		}
		return []*record.DatapathRecord{
			&record.DatapathRecord{
				Policy:   *policy,
				Src:      src,
				Endpoint: endpoint,
				Action:   action,
				Init:     init,
			},
		}, nil
	}

	records := []*record.DatapathRecord{}
	for _, port := range dest.Ports {
		endpoint := record.DatapathEndpoint{
			EP:   ep,
			Port: port,
		}
		records = append(records, &record.DatapathRecord{
			Policy:   *policy,
			Src:      src,
			Endpoint: endpoint,
			Action:   action,
			Init:     init,
		})
	}
	return records, nil
}

func (state *PolicyState) addDestCIDRRecords(
	policy *record.Policy,
	dest *types.TetragonNetworkDestination,
	subject *types.TetragonNetworkSubject,
	podSubject *types.ProcessTreeKey,
	action *record.DatapathAction,
) ([]*record.DatapathRecord, error) {
	records := []*record.DatapathRecord{}

	for _, process := range subject.InProcessName {
		self, err := prog.GetBinaryId(process)
		if err != nil {
			logger.GetLogger().WithError(err).Warn("add cidr binary id error")
			continue
		}
		processSrc := &types.ProcessTreeKey{
			NSID:  podSubject.NSID,
			Depth: 0,
			Self:  self,
			Path:  [8]uint64{0, 0, 0, 0, 0, 0, 0, 0},
		}
		r, err := state.addDestSrcCIDRRecords(policy, dest, processSrc, action, true)
		if err != nil {
			logger.GetLogger().WithError(err).Warn("add DestCIDR recrods failed")
		} else {
			records = append(records, r...)
		}
	}

	if len(subject.InProcessName) == 0 {
		r, err := state.addDestSrcCIDRRecords(policy, dest, podSubject, action, true)
		if err != nil {
			logger.GetLogger().WithError(err).Warn("add DestCIDR recrods failed")
		} else {
			records = append(records, r...)
		}
	}

	return records, nil

}
