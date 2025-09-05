package nxos

import (
	"context"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	model "github.com/isovalent/hubble-fgs/pkg/nxosmodel"
	"github.com/openconfig/ygot/ytypes"
)

func (n *Nxos) getHaIp(ctx context.Context) error {
	jstrs, err := n.gnmiGet(ctx, "/System/sas-items/state-items/agent-items")
	if err != nil {
		logger.GetLogger().Error("Fail to get agent-items", logfields.Error, err)
		return err
	}
	logger.GetLogger().Debug("jstrs:", "jstrs", jstrs)
	if len(jstrs) > 0 && len(jstrs[0]) > 0 {
		items := &model.Cisco_NX_OSDevice_System_SasItems_StateItems_AgentItems{}
		opts := []ytypes.UnmarshalOpt{&ytypes.IgnoreExtraFields{}}
		err = model.Unmarshal([]byte(jstrs[0]), items, opts...)
		if err != nil {
			logger.GetLogger().Error("Fail to unmarshal spcmn-items", logfields.Error, err)
			return err
		} else {
			err = n.updtSasStateAgent(ctx, items)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
