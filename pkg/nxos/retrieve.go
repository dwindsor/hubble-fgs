// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package nxos

import (
	"context"
	"strconv"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/config/library"
	model "github.com/isovalent/hubble-fgs/pkg/nxosmodel"
	hav1 "github.com/isovalent/hubble-fgs/pkg/proto/ha/v1"
	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
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

// getAgentUpgradeState retrieves the agent state from /System/sas-items/state-items/agent-items.
func (n *Nxos) getAgentUpgradeState(ctx context.Context) (model.E_Cisco_NX_OSDevice_SasAgentUpgradeStateE, error) {
	logger.GetLogger().Debug("Retrieving agent upgrade state")

	upgradeState := model.Cisco_NX_OSDevice_SasAgentUpgradeStateE_UNSET
	jstrs, err := n.gnmiGet(ctx, "/System/sas-items/state-items/agent-items")
	if err != nil {
		logger.GetLogger().Error("Fail to get agent-items", logfields.Error, err)
		return upgradeState, err
	}
	if len(jstrs) > 0 && len(jstrs[0]) > 0 {
		items := &model.Cisco_NX_OSDevice_System_SasItems_StateItems_AgentItems{}
		opts := []ytypes.UnmarshalOpt{&ytypes.IgnoreExtraFields{}}
		err = model.Unmarshal([]byte(jstrs[0]), items, opts...)
		if err != nil {
			logger.GetLogger().Error("Fail to unmarshal agent-items", logfields.Error, err)
		} else {
			// Only the first "hypershield" entry is considered.
			for svc, agent := range items.SasAgentList {
				if svc != "hypershield" {
					logger.GetLogger().Debug("Unexpected service", "svc", svc)
					continue
				}
				logger.GetLogger().Info("AgentUpgradeState", "state", agent.AgentUpgradeState.String())
				return agent.AgentUpgradeState, nil
			}
		}
	}
	// Fallback: if no valid agent upgrade state is found for "hypershield", return unknown agent upgrade state.
	return upgradeState, nil
}

// getAdmissionAndConnectionStates retrieves the admission and connection states from the device.
func (n *Nxos) getAdmissionAndConnectionStates(ctx context.Context) error {
	logger.GetLogger().Debug("Retrieving admission and connection states")

	// Get the admission and connection states from the device
	jstrs, err := n.gnmiGet(ctx, svcInst+"/scontroller-items/ext-items")
	if err != nil {
		logger.GetLogger().Error("Fail to get scontroller-items/ext-items", logfields.Error, err)
		return err
	}
	if len(jstrs) > 0 && len(jstrs[0]) > 0 {
		items := &model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_ScontrollerItems_ExtItems{}
		opts := []ytypes.UnmarshalOpt{&ytypes.IgnoreExtraFields{}}
		err = model.Unmarshal([]byte(jstrs[0]), items, opts...)
		if err != nil {
			logger.GetLogger().Error("Fail to unmarshal scontroller-items/ext-items", logfields.Error, err)
		} else {
			logger.GetLogger().Debug("scontroller/ext-items:", "items", items)
			n.Ctrlr.AdmissionStatus = items.AdmissionStatus
			n.Ctrlr.ConnectionStatus = items.ConnectionStatus
			if items.RejectReason != nil {
				n.Ctrlr.RejectReason = *items.RejectReason
			}
			if items.Version != nil {
				n.Ctrlr.Version = *items.Version
			}
		}
	} else {
		logger.GetLogger().Debug("Set admission and connection status to default")
		n.Ctrlr.AdmissionStatus = model.Cisco_NX_OSDevice_Sas_CommonStateE_unknown
		n.Ctrlr.ConnectionStatus = model.Cisco_NX_OSDevice_Sas_CommonStateE_unknown
	}
	return nil
}

// getProxyConfig retrieves the proxy configuration from the device.
func (n *Nxos) getProxyConfig(ctx context.Context) error {
	logger.GetLogger().Debug("Retrieving proxy configuration")
	n.RLock()
	proxySvr := n.Ctrlr.ProxySvr != ""
	proxyPort := n.Ctrlr.ProxyPort != 0
	n.RUnlock()

	if proxySvr && proxyPort {
		logger.GetLogger().Debug("Proxy server and port already set", "proxySvr", n.Ctrlr.ProxySvr, "proxyPort", n.Ctrlr.ProxyPort)
		return nil
	}

	jstrs, err := n.gnmiGet(ctx, svcInst+"/scontroller-items")
	if err != nil {
		logger.GetLogger().Error("Fail to get scontroller-items", logfields.Error, err)
		return err
	}
	// logger.GetLogger().Debug("jstrs: %v", jstrs)
	if len(jstrs) > 0 && len(jstrs[0]) > 0 {
		items := &model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_ScontrollerItems{}
		opts := []ytypes.UnmarshalOpt{&ytypes.IgnoreExtraFields{}}
		err = model.Unmarshal([]byte(jstrs[0]), items, opts...)
		if err != nil {
			logger.GetLogger().Error("Fail to unmarshal scontroller-items", logfields.Error, err)
		} else {
			// logger.GetLogger().Debug("scontroller-items: %+v", items)
			n.Lock()
			defer n.Unlock()
			if items.HttpsProxySvr != nil {
				n.Ctrlr.ProxySvr = *items.HttpsProxySvr
			}
			if items.HttpsProxyPort != nil {
				n.Ctrlr.ProxyPort = *items.HttpsProxyPort
			}
			n.setProxy(ctx)
		}
	} else {
		logger.GetLogger().Debug("No https-proxy configured")
	}
	return nil
}

// getModelAndVersion retrieves the model and version from the device.
func (n *Nxos) getModelAndVersion(ctx context.Context) error {
	logger.GetLogger().Debug("Retrieving model and version")

	mstrs, err := n.gnmiGet(ctx, "/System/ch-items/spbp-items/spcmn-items/pdNum")
	if err != nil {
		logger.GetLogger().Error("Fail to get model", logfields.Error, err)
		return err
	}
	if len(mstrs) > 0 {
		if model, err := strconv.Unquote(mstrs[0]); err == nil {
			n.Model = model
		} else {
			n.Model = mstrs[0]
		}
	}
	vstrs, err := n.gnmiGet(ctx, "/System/ch-items/supslot-items/SupCSlot-list/sup-items/swVer")
	if err != nil {
		logger.GetLogger().Error("Fail to get model", logfields.Error, err)
		return err
	}
	if len(vstrs) > 0 {
		if model, err := strconv.Unquote(vstrs[0]); err == nil {
			n.SwVer = model
		} else {
			n.SwVer = vstrs[0]
		}
	}
	logger.GetLogger().Debug("sswitch", "model", n.Model, "SwVer", n.SwVer)
	return nil
}

// getSerialNum retrieves the serial number from the device.
func (n *Nxos) getSerialNum(ctx context.Context) error {
	logger.GetLogger().Debug("Retrieving serial number")
	n.RLock()
	serNumSet := n.SerNum != ""
	n.RUnlock()

	if serNumSet {
		logger.GetLogger().Debug("Serial number already set", "sernum", n.SerNum)
		return nil
	}

	jstrs, err := n.gnmiGet(ctx, "/System/ch-items/spbp-items/spcmn-items")
	if err != nil {
		logger.GetLogger().Error("Fail to get spcmn-items", logfields.Error, err)
		return err
	}
	logger.GetLogger().Debug("jstrs", "jstrs", jstrs)
	if len(jstrs) > 0 && len(jstrs[0]) > 0 {
		items := &model.Cisco_NX_OSDevice_System_ChItems_SpbpItems_SpcmnItems{}
		opts := []ytypes.UnmarshalOpt{&ytypes.IgnoreExtraFields{}}
		err = model.Unmarshal([]byte(jstrs[0]), items, opts...)
		if err != nil {
			logger.GetLogger().Error("Fail to unmarshal spcmn-items", logfields.Error, err)
		} else if items.SerNum != nil {
			n.Lock()
			n.SerNum = *items.SerNum
			n.Unlock()
			logger.GetLogger().Debug("sswitch", "sernum", n.SerNum)
		}
	}

	// Updating serial number in the dpu config atomically
	err = library.GetRepository().UpdateConfig(v1alpha.ConfigType_CONFIG_TYPE_DPU, func(existing *v1alpha.ConfigObject) (*v1alpha.ConfigObject, error) {
		var dpuConfig *v1alpha.DpuConfig
		if existing != nil && existing.GetConfigDpu() != nil {
			dpuConfig = existing.GetConfigDpu()
		} else {
			dpuConfig = &v1alpha.DpuConfig{}
		}
		dpuConfig.SerialNumber = n.SerNum
		return &v1alpha.ConfigObject{
			Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
			Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
			Config: &v1alpha.ConfigObject_ConfigDpu{ConfigDpu: dpuConfig},
		}, nil
	})
	if err != nil {
		logger.GetLogger().Error("Failed to update dpu config with serial number", "error", err)
	}
	return nil
}

func (n *Nxos) getLocalSvcState(ctx context.Context) {
	n.Ha.NxStates.SvcState = hav1.SERVICE_STATE_SVC_FAILURE
	jstrs, err := n.gnmiGet(ctx, svcInst+"/fwpolicystate-items/ext-items")
	if err != nil {
		logger.GetLogger().Debug("Fail to get fwpolicystate-items/ext-items", "error", err.Error())
		return
	}
	logger.GetLogger().Debug("jstrs", "", jstrs)
	if len(jstrs) > 0 && len(jstrs[0]) > 0 {
		items := &model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicystateItems_ExtItems{}
		opts := []ytypes.UnmarshalOpt{&ytypes.IgnoreExtraFields{}}
		err = model.Unmarshal([]byte(jstrs[0]), items, opts...)
		if err != nil {
			logger.GetLogger().Error("Fail to unmarshal ext-items",
				logfields.Error, err)
			return
		} else {
			logger.GetLogger().Debug("LocalSvcState", "", items.LocalSvcState)
			switch items.LocalSvcState {
			case model.Cisco_NX_OSDevice_SasSvcStateE_ready:
				n.Ha.NxStates.SvcState = hav1.SERVICE_STATE_SVC_SUCCESS

			case model.Cisco_NX_OSDevice_SasSvcStateE_not_ready:

			default:
				logger.GetLogger().Debug("unexpected LocalSvcState")
			}
		}
	}
}

func (n *Nxos) getLocalHaState(ctx context.Context) {
	n.Ha.NxStates.HaState = hav1.HA_STATE_NO_HA
	jstrs, err := n.gnmiGet(ctx, svcInst+"/ha-items/ext-items")
	if err != nil {
		logger.GetLogger().Debug("Fail to get ha-items/ext-items", "error", err.Error())
		return
	}
	logger.GetLogger().Debug("jstrs", "", jstrs)
	if len(jstrs) > 0 && len(jstrs[0]) > 0 {
		items := &model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_HaItems_ExtItems{}
		opts := []ytypes.UnmarshalOpt{&ytypes.IgnoreExtraFields{}}
		err = model.Unmarshal([]byte(jstrs[0]), items, opts...)
		if err != nil {
			logger.GetLogger().Error("Fail to unmarshal ext-items",
				logfields.Error, err)
			return
		} else {
			logger.GetLogger().Debug("LocalHaState", "", items.AgentHaState)
			switch items.AgentHaState {
			case model.Cisco_NX_OSDevice_SasAgentHaStateE_ha_ready:
				n.Ha.NxStates.HaState = hav1.HA_STATE_HA_READY

			case model.Cisco_NX_OSDevice_SasAgentHaStateE_ha_not_ready:
				n.Ha.NxStates.HaState = hav1.HA_STATE_HA_NOTREADY

			case model.Cisco_NX_OSDevice_SasAgentHaStateE_ha_switchover:
				n.Ha.NxStates.HaState = hav1.HA_STATE_HA_SWITCHOVER

			case model.Cisco_NX_OSDevice_SasAgentHaStateE_no_ha:

			default:
				logger.GetLogger().Debug("unexpected LocalHaState")
			}
		}
	}
}
