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
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/config/library"
	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"
	model "github.com/isovalent/hubble-fgs/pkg/nxosmodel"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
	"github.com/openconfig/gnmi/proto/gnmi"
)

const (
	envToken       = "HYPERSHIELD_TOKEN"
	envHttpProxy   = "http_proxy"
	envHttpProxy2  = "HTTP_PROXY"
	envHttpsProxy  = "https_proxy"
	envHttpsProxy2 = "HTTPS_PROXY"
)

func sanitizePath(path string, validPaths []string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	for _, validPath := range validPaths {
		absValidPath, err := filepath.Abs(validPath)
		if err != nil {
			return err
		}

		if strings.HasPrefix(absPath, absValidPath) {
			return nil
		}
	}
	return fmt.Errorf("path %s is not within any valid working paths", path)
}

func (n *Nxos) delVbGlobal(ctx context.Context, isBd bool, name string) error {
	logger.GetLogger().Debug("delVbGlobal", "name", name, "isBd", isBd)

	var vb VrfBd
	var ok bool
	if isBd {
		vb, ok = n.Bds[name]
		if !ok {
			err := errors.New("BD not found")
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	} else {
		vb, ok = n.Vrfs[name]
		if !ok {
			err := errors.New("VRF not found")
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}

	if !vb.IsGlobal {
		logger.GetLogger().Error("IsGlobal is expected to be true")
	} else {
		vb.IsGlobal = false
	}
	if !vb.IsService {
		var fname string
		if isBd {
			delete(n.Bds, name)
			fname = filepath.Join(rootVolatile, "bd-"+name+".json")
		} else {
			delete(n.Vrfs, name)
			fname = filepath.Join(rootVolatile, "vrf-"+name+".json")
		}

		err := sanitizePath(fname, []string{rootVolatile})
		if err != nil {
			return errors.Join(err,
				fmt.Errorf("name contains malicious path"))
		}
		err = n.remove(ctx, fname)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	} else {
		if isBd {
			n.Bds[name] = vb
		} else {
			n.Vrfs[name] = vb
		}
		if n.Stage == StageNormal {
			n.delServiceVb(ctx, isBd, vb)
		}
	}

	if isBd {
		err := n.doVlanPolicyMapUpdate()
		if err != nil {
			logger.GetLogger().Error("failed to remove service bd", logfields.Error, err, "bd-name", vb.Name)
		}
	} else {
		err := n.doVRFPolicyMapUpdate()
		if err != nil {
			logger.GetLogger().Error("failed to remove service vrf", logfields.Error, err, "vrf-name", vb.Name)
		}
	}
	return nil
}

func (n *Nxos) delVbService(ctx context.Context, isBd bool, name string) error {
	logger.GetLogger().Debug("delVbService", "name", name, "isBd", isBd)

	var vb VrfBd
	var ok bool
	if isBd {
		vb, ok = n.Bds[name]
		if !ok {
			err := errors.New("BD not found")
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	} else {
		vb, ok = n.Vrfs[name]
		if !ok {
			err := errors.New("VRF not found")
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}

	if !vb.IsService {
		logger.GetLogger().Error("IsService is expected to be true")
	} else {
		vb.IsService = false
	}
	if !vb.IsGlobal {
		var fname string
		if isBd {
			delete(n.Bds, name)
			fname = filepath.Join(rootVolatile, "bd-"+name+".json")
		} else {
			delete(n.Vrfs, name)
			fname = filepath.Join(rootVolatile, "vrf-"+name+".json")
		}
		err := sanitizePath(fname, []string{rootVolatile})
		if err != nil {
			return errors.Join(err,
				fmt.Errorf("name contains malicious path"))
		}
		err = n.remove(ctx, fname)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	} else {
		if isBd {
			n.Bds[name] = vb
		} else {
			n.Vrfs[name] = vb
		}
		if n.Stage == StageNormal {
			n.delServiceVb(ctx, isBd, vb)
		}
	}

	if isBd {
		err := n.doVlanPolicyMapUpdate()
		if err != nil {
			logger.GetLogger().Error("failed to remove service bd", logfields.Error, err, "bd-name", vb.Name)
		}
	} else {
		err := n.doVRFPolicyMapUpdate()
		if err != nil {
			logger.GetLogger().Error("failed to remove service vrf", logfields.Error, err, "vrf-name", vb.Name)
		}
	}
	return nil
}

func (n *Nxos) delSvcInstance(ctx context.Context, elem *gnmi.PathElem) {

	key := elem.GetKey()
	name := key["name"]
	logger.GetLogger().Debug("Delete service instance", "name", name)

	if name != "hypershield" {
		logger.GetLogger().Debug("Service instance is not hypershield, ignored")
		return
	}

	n.delDpuPortRange(ctx)
	n.remove(ctx, allocFname)
	// Do a graceful restart of the agent, without service redirect cleanp.
	n.GracefulRestartAgent(ctx, false)
}

func (n *Nxos) delSvcFw(ctx context.Context) {
	logger.GetLogger().Debug("Delete service firewall")
	n.IsDelSvcFw = true

	n.remove(ctx, allocFname)
	// Do a graceful restart of the agent, with cleanup.
	n.GracefulRestartAgent(ctx, true)
}

func (n *Nxos) updtInst(ctx context.Context, items *model.Cisco_NX_OSDevice_System_InstItems) error {
	// logger.GetLogger().Debug("updtInst %+v", *items)

	list := []*model.Cisco_NX_OSDevice_System_InstItems_InstList{}
	for _, inst := range items.InstList {
		list = append(list, inst)
	}

	err := n.updtInstList(ctx, list)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}

	return nil
}

func (n *Nxos) addServiceVb(ctx context.Context, isBd bool, noRps []VrfBd, rps []VrfBd) error {
	logger.GetLogger().Debug("addServiceVb", "isBd", isBd, "noRps", rps)

	if len(rps) > 0 {
		err := n.progRepinning(ctx, isBd, rps)
		if err != nil {
			logger.GetLogger().Error("Fail to do repinning", logfields.Error, err)
			return err
		}
	}
	if len(noRps) > 0 {
		err := n.setFwPolicyState(ctx, isBd, noRps)
		if err != nil {
			logger.GetLogger().Error("Fail to set fw policy state", logfields.Error, err)
			return err
		}
		err = n.setServiceRedir(ctx, isBd, noRps)
		if err != nil {
			logger.GetLogger().Error("Fail to set service redir", logfields.Error, err)
			return err
		}
	}
	return nil
}

func (n *Nxos) delServiceVb(ctx context.Context, isBd bool, vb VrfBd) error {
	logger.GetLogger().Debug("delServiceVb: name %s, isBd %v", vb.Name, isBd)

	if !n.InService {
		logger.GetLogger().Error("Skip due to not in service")
		return nil
	}

	err := n.delFwPolicyState(ctx, isBd, vb.Name)
	if err != nil {
		logger.GetLogger().Error("Fail to delete fw policy state", logfields.Error, err)
	}
	err = n.delServiceRedir(ctx, isBd, vb.Name)
	if err != nil {
		logger.GetLogger().Error("Fail to delete service redir", logfields.Error, err)
	}

	if isBd {
		delete(n.Alloc.BdDpus, vb.Name)
	} else {
		gid, ok := n.Alloc.Gids[vb.Name]
		if ok {
			delete(n.GidsInUse, gid)
		}
		delete(n.Alloc.Gids, vb.Name)
		delete(n.Alloc.VrfDpus, vb.Name)
	}
	n.store(ctx, allocFname, n.Alloc)

	return nil
}

func (n *Nxos) updtInstList(ctx context.Context, instList []*model.Cisco_NX_OSDevice_System_InstItems_InstList) error {
	// logger.GetLogger().Debug("updtInstList: %+v", *list)
	policyMapUpdate := false

	vrfs := []VrfBd{}
	for _, list := range instList {
		if list.Name == nil {
			err := errors.New("no VRF name")
			logger.GetLogger().Error("", logfields.Error, err)
			continue
		}

		name := *list.Name
		logger.GetLogger().Debug("Updating global VRF", "name", name)
		v, ok := n.Vrfs[name]
		if ok {
			logger.GetLogger().Debug("VRF already exists")
		} else {
			v.Name = name
		}
		if !v.IsGlobal {
			v.IsGlobal = true
			if v.IsService {
				n.doPinning(ctx, false, &v)
				policyMapUpdate = true
			}
			n.Vrfs[name] = v

			fname := filepath.Join(rootVolatile, "vrf-"+name+".json")
			err := sanitizePath(fname, []string{rootVolatile})
			if err != nil {
				return errors.Join(err,
					fmt.Errorf("VRF name contains malicious path"))
			}
			n.store(ctx, fname, v)
			if n.Stage == StageNormal {
				vrfs = append(vrfs, v)
			}
		}
	}

	if policyMapUpdate {
		err := n.doVRFPolicyMapUpdate()
		if err != nil {
			logger.GetLogger().Error("Fail to update VRF policy map", logfields.Error, err)
			return err
		}
	}

	if len(vrfs) > 0 {
		return n.addServiceVb(ctx, false, vrfs, nil)
	}

	return nil
}

func (n *Nxos) updtBd(ctx context.Context, items *model.Cisco_NX_OSDevice_System_BdItems) error {
	logger.GetLogger().Debug("updtBd", "item", *items)

	if items.BdItems != nil {
		err := n.updtBdBd(ctx, items.BdItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}

	return nil
}

func (n *Nxos) updtBdBd(ctx context.Context, items *model.Cisco_NX_OSDevice_System_BdItems_BdItems) error {
	// logger.GetLogger().Debug("updtInst %+v", *items)

	list := []*model.Cisco_NX_OSDevice_System_BdItems_BdItems_BDList{}
	for _, bd := range items.BDList {
		list = append(list, bd)
	}

	err := n.updtBdBdBDList(ctx, list)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}

	return nil
}

func (n *Nxos) updtBdBdBDList(ctx context.Context, bdList []*model.Cisco_NX_OSDevice_System_BdItems_BdItems_BDList) error {
	logger.GetLogger().Debug("updtBdBdBDList", "bd", bdList)
	policyMapUpdate := false

	bds := []VrfBd{}
	for _, bd := range bdList {
		if bd.FabEncap == nil {
			err := errors.New("no VLAN specified in BD")
			logger.GetLogger().Error("", logfields.Error, err)
			continue
		}

		name := *bd.FabEncap
		logger.GetLogger().Debug("Updating global BD", "name", name)
		b, ok := n.Bds[name]
		if ok {
			logger.GetLogger().Debug("BD already exists")
		} else {
			b.Name = name
		}
		if !b.IsGlobal {
			b.IsGlobal = true
			if b.IsService {
				n.doPinning(ctx, true, &b)
				policyMapUpdate = true
			}
			n.Bds[name] = b

			fname := filepath.Join(rootVolatile, "bd-"+name+".json")
			err := sanitizePath(fname, []string{rootVolatile})
			if err != nil {
				return errors.Join(err,
					fmt.Errorf("BD name contains malicious path"))
			}
			n.store(ctx, fname, b)
			if n.Stage == StageNormal {
				bds = append(bds, b)
			}
		}
	}
	if policyMapUpdate {
		err := n.doVlanPolicyMapUpdate()
		if err != nil {
			logger.GetLogger().Error("Fail to update VLAN policy map", logfields.Error, err)
			return err
		}
	}
	if len(bds) > 0 {
		return n.addServiceVb(ctx, true, bds, nil)
	}

	return nil
}

func (n *Nxos) updtSas(ctx context.Context, items *model.Cisco_NX_OSDevice_System_SasItems) error {
	logger.GetLogger().Debug("updtSas")

	if items.DpuItems != nil {
		err := n.updtSasDpu(ctx, items.DpuItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}
	if items.SvcItems != nil {
		err := n.updtSasSvc(ctx, items.SvcItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}
	if items.StateItems != nil {
		err := n.updtSasState(ctx, items.StateItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}

	if items.VolatiledataItems != nil {
		err := n.updtSasVolatiledata(ctx, items.VolatiledataItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}
	if items.GlobalpolItems != nil {
		err := n.updtSasGlobalpol(ctx, items.GlobalpolItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}
	return nil
}

func (n *Nxos) updtSasSvc(ctx context.Context, items *model.Cisco_NX_OSDevice_System_SasItems_SvcItems) error {
	logger.GetLogger().Debug("updtSasSvc")

	if items.SvcinstItems != nil {
		err := n.updtSasSvcSvcinst(ctx, items.SvcinstItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}
	return nil
}

func (n *Nxos) updtSasSvcSvcinst(ctx context.Context, items *model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems) error {
	logger.GetLogger().Debug("updtSasSvcinst")

	for k, v := range items.SvcInstanceList {
		if k != "hypershield" {
			logger.GetLogger().Debug("Skip service", "name", k)
			continue
		}
		if v == nil {
			logger.GetLogger().Debug("Inst missing for keys", "key", k)
			continue
		}
		err := n.updtSasSvcSvcinstSvcInstance(ctx, v)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}
	return nil
}

func (n *Nxos) setInService(_ context.Context, insvc bool) bool {
	prev := n.InService
	if prev != insvc {
		n.InService = insvc
		return true
	}
	return false
}

func (n *Nxos) updtSasSvcSvcinstSvcInstance(ctx context.Context, items *model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList) error {
	// logger.GetLogger().Debug("updtSasSvcinstSvcInstance")

	// items.Name
	if items.ScontrollerItems != nil {
		err := n.updtSasSvcSvcinstSvcInstanceScontroller(ctx, items.ScontrollerItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}
	if items.SagentItems != nil {
		err := n.updtSasSvcSvcinstSvcInstanceSagent(ctx, items.SagentItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}
	if items.HaItems != nil {
		err := n.updtSasSvcSvcinstSvcInstanceHa(ctx, items.HaItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}

	if items.FwpolicyItems != nil {
		err := n.updtSasSvcSvcinstSvcInstanceFwpolicy(ctx, items.FwpolicyItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}
	//if items.FwpolicystateItems != nil {
	//}
	return nil
}

func (n *Nxos) updtSasSvcSvcinstSvcInstanceScontroller(ctx context.Context, items *model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_ScontrollerItems) error {

	if items.HttpsProxySvr != nil && n.Ctrlr.ProxySvr != *items.HttpsProxySvr {
		logger.GetLogger().Debug("proxy svr updated: restart agw")
		n.GracefulRestartAgent(ctx, false)
	}
	if items.HttpsProxyPort != nil && n.Ctrlr.ProxyPort != *items.HttpsProxyPort {
		logger.GetLogger().Debug("proxy port updated: restart agw")
		n.GracefulRestartAgent(ctx, false)
	}
	return nil
}

func (n *Nxos) updtSasSvcSvcinstSvcInstanceSagent(_ context.Context, items *model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_SagentItems) error {

	// items.FlowExportSourceIp
	// items.MigrationSourceIp
	return nil
}

func (n *Nxos) updtSasSvcSvcinstSvcInstanceFwpolicy(ctx context.Context, items *model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicyItems) error {

	n.Configured = true
	if items.OperState == model.Cisco_NX_OSDevice_Sas_SasInstState_in_service {
		modified := n.setInService(ctx, true)
		if modified {
			logger.GetLogger().Debug("Hypershield is enabled")
			if n.Stage == StageEnable {
				n.Wait.In() <- WakeEnable
			}
			// Trigger HA reconciliation when transitioning to in-service
			// to ensure GID and VLAN allocations are consistent with peer
			go n.TriggerHAReconciliation(ctx)
		}
	} else if items.OperState == model.Cisco_NX_OSDevice_Sas_SasInstState_out_of_service {
		modified := n.setInService(ctx, false)
		if modified {
			logger.GetLogger().Debug("Hypershield is disabled")
			// Graceful restart the agent with cleanup.
			n.GracefulRestartAgent(ctx, true)
		}
	}

	if items.IpvrfItems != nil {
		err := n.updtSasSvcSvcinstSvcInstanceFwpolicyIpvrf(ctx, items.IpvrfItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}

	if items.BdItems != nil {
		err := n.updtSasSvcSvcinstSvcInstanceFwpolicyBd(ctx, items.BdItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}

	return nil
}

func (n *Nxos) updtSasSvcSvcinstSvcInstanceFwpolicyIpvrf(ctx context.Context, items *model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicyItems_IpvrfItems) error {

	if items.DomItems != nil {
		err := n.updtSasSvcSvcinstSvcInstanceFwpolicyIpvrfDom(ctx, items.DomItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}
	return nil
}

func (n *Nxos) updtSasSvcSvcinstSvcInstanceFwpolicyIpvrfDom(ctx context.Context, items *model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicyItems_IpvrfItems_DomItems) error {

	domList := []*model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicyItems_IpvrfItems_DomItems_DomList{}
	for k, v := range items.DomList {
		if v == nil {
			logger.GetLogger().Debug("Empty domList for vrf", "key", k)
			continue
		}
		domList = append(domList, v)
	}
	err := n.updtSasSvcSvcinstSvcInstanceFwpolicyIpvrfDomDom(ctx, domList)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	return nil
}

func (n *Nxos) doVRFPolicyMapUpdate() error {
	var networkConfig *v1alpha.NetworkConfig

	vrfMap := switchpolicy.NewL3Networks()
	vrfs := make([]*v1alpha.Vrf, 0)
	for _, vrf := range n.Vrfs {
		// VRFs are only active / ready for traffic if they are both global and service
		if !vrf.IsGlobal || !vrf.IsService {
			continue
		}
		vrfName := switchpolicy.VrfName(vrf.Name)
		vid, ok := n.Alloc.Gids[vrf.Name]
		if !ok {
			continue
		}
		vrfId := switchpolicy.VrfGID(vid)
		err := vrfMap.Add(vrfName, vrfId)
		if err != nil {
			logger.GetLogger().Error("vrfMap add failed", "vrf", vrf.Name, "gid", vid, logfields.Error, err)
			return err
		}
		// Also build the VRF slice for the config
		vrfs = append(vrfs, &v1alpha.Vrf{
			Name: vrf.Name,
			Id:   uint32(vid),
		})

	}
	err := n.policyHandler.SetL3Networks(vrfMap)
	if err != nil {
		return err
	}

	// Update the configuration in the repository
	err = library.GetRepository().UpdateConfig(v1alpha.ConfigType_CONFIG_TYPE_NETWORK, func(existing *v1alpha.ConfigObject) (*v1alpha.ConfigObject, error) {
		networkConfig = &v1alpha.NetworkConfig{}
		networkConfig.Vrfs = vrfs

		return &v1alpha.ConfigObject{
			Type:   v1alpha.ConfigType_CONFIG_TYPE_NETWORK,
			Source: v1alpha.ConfigSource_CONFIG_SOURCE_LOCAL,
			Config: &v1alpha.ConfigObject_NetworkConfig{NetworkConfig: networkConfig},
		}, nil
	})

	if err != nil {
		logger.GetLogger().Error("Failed to update network config", logfields.Error, err)
		return err
	}
	return nil
}

func (n *Nxos) doVlanPolicyMapUpdate() error {
	logger.GetLogger().Debug("doVlanPolicyMapUpdate")

	for _, vlan := range n.Bds {
		// VLANs are only active / ready for traffic if they are both global and service
		if !vlan.IsGlobal || !vlan.IsService {
			continue
		}

		// TODO: Updating NetworkConfig
	}

	return nil
}

func (n *Nxos) addVbService(ctx context.Context, isBd bool, names []*string, affinities []*uint16) error {
	logger.GetLogger().Debug("addVbService: isBd", "isBd", isBd)
	policyMapUpdate := false

	noRps := []VrfBd{}
	rps := []VrfBd{}
	for idx, name := range names {
		if name == nil {
			logger.GetLogger().Error("name missing")
			continue
		}
		var vb VrfBd
		var ok bool
		if isBd {
			logger.GetLogger().Debug("BD is configured as FW svc BD", "name", *name)
			vb, ok = n.Bds[*name]
		} else {
			logger.GetLogger().Debug("VRF is configured as FW svc VRF", "name", *name)
			vb, ok = n.Vrfs[*name]
		}
		if !ok {
			vb.Name = *name
		} else {
			logger.GetLogger().Debug("existing VRF/BD config", "vb", vb)
		}
		if !vb.IsService || (affinities[idx] != nil && vb.Affinity != *affinities[idx]) {
			var rp bool
			if affinities[idx] != nil && *affinities[idx] != 0 {
				logger.GetLogger().Debug("VRF/BD has static pinning", "name", *name, "affinity", *affinities[idx])
				vb.IsStatic = true
				vb.Affinity = *affinities[idx]
			} else {
				vb.IsStatic = false
				vb.Affinity = 0
			}

			if vb.IsService {
				rp = true
			} else {
				vb.IsService = true
			}
			var skip bool
			if vb.IsGlobal {
				prev := vb.DpuPinned
				n.doPinning(ctx, isBd, &vb)
				if rp && prev == vb.DpuPinned {
					// static and dynamic are same, skip
					logger.GetLogger().Debug("Skip svc redir reprog")
					skip = true
				}
				policyMapUpdate = true
			}

			var fname string
			if isBd {
				n.Bds[*name] = vb
				fname = filepath.Join(rootVolatile, "bd-"+*name+".json")
			} else {
				n.Vrfs[*name] = vb
				fname = filepath.Join(rootVolatile, "vrf-"+*name+".json")
			}
			err := sanitizePath(fname, []string{rootVolatile})
			if err != nil {
				return errors.Join(err,
					fmt.Errorf("VRF/BD name contains malicious path"))
			}
			n.store(ctx, fname, vb)

			if vb.IsGlobal && n.Stage == StageNormal && !skip {
				if rp {
					rps = append(rps, vb)
				} else {
					noRps = append(noRps, vb)
				}
			}
		}
	}

	if policyMapUpdate {
		if isBd {
			err := n.doVlanPolicyMapUpdate()
			if err != nil {
				logger.GetLogger().Error("Fail to update VLAN policy map", logfields.Error, err)
				return err
			}
		} else {
			err := n.doVRFPolicyMapUpdate()
			if err != nil {
				logger.GetLogger().Error("Fail to update VRF policy map", logfields.Error, err)
				return err
			}
		}
	}

	return n.addServiceVb(ctx, isBd, noRps, rps)
}

func (n *Nxos) updtSasSvcSvcinstSvcInstanceFwpolicyIpvrfDomDom(ctx context.Context, list []*model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicyItems_IpvrfItems_DomItems_DomList) error {

	names := []*string{}
	affinities := []*uint16{}
	for _, items := range list {
		if items.Name == nil {
			logger.GetLogger().Error("VRF name missing")
			continue
		}
		names = append(names, items.Name)
		affinities = append(affinities, items.Affinity)
	}
	err := n.addVbService(ctx, false, names, affinities)
	if err != nil {
		logger.GetLogger().Error("Fail to add service VRF/BD", logfields.Error, err)
	}
	return err
}

func (n *Nxos) updtSasSvcSvcinstSvcInstanceFwpolicyBd(ctx context.Context, items *model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicyItems_BdItems) error {

	if items.VlanItems != nil {
		err := n.updtSasSvcSvcinstSvcInstanceFwpolicyBdVlan(ctx, items.VlanItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}
	return nil
}

func (n *Nxos) updtSasSvcSvcinstSvcInstanceFwpolicyBdVlan(ctx context.Context, items *model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicyItems_BdItems_VlanItems) error {

	list := []*model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicyItems_BdItems_VlanItems_VlanList{}
	for k, v := range items.VlanList {
		if v == nil {
			logger.GetLogger().Debug("Empty VlanItems for BD", "bd", k)
			continue
		}
		list = append(list, v)
	}
	err := n.updtSasSvcSvcinstSvcInstanceFwpolicyBdVlanVlan(ctx, list)
	if err != nil {
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}
	return nil

}

func (n *Nxos) updtSasSvcSvcinstSvcInstanceFwpolicyBdVlanVlan(ctx context.Context, items []*model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_FwpolicyItems_BdItems_VlanItems_VlanList) error {
	logger.GetLogger().Debug("updtSasSvcSvcinstSvcInstanceFwpolicyBdVlanVlan")

	names := []*string{}
	affinities := []*uint16{}
	for _, item := range items {
		if item.VlanId == nil {
			logger.GetLogger().Error("BD name missing")
			continue
		}
		names = append(names, item.VlanId)
		affinities = append(affinities, item.Affinity)
	}
	err := n.addVbService(ctx, true, names, affinities)
	if err != nil {
		logger.GetLogger().Error("Fail to add service VRF/BD", logfields.Error, err)
	}
	return err
}

func (n *Nxos) updtSasState(ctx context.Context, items *model.Cisco_NX_OSDevice_System_SasItems_StateItems) error {
	// logger.GetLogger().Debug("updtSasState")

	if items.AgentItems != nil {
		err := n.updtSasStateAgent(ctx, items.AgentItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}
	return nil
}

func (n *Nxos) updtSasStateAgent(_ context.Context, items *model.Cisco_NX_OSDevice_System_SasItems_StateItems_AgentItems) error {

	for svc, agent := range items.SasAgentList {
		if svc != "hypershield" {
			logger.GetLogger().Debug("Unexpected svc", "name", svc)
			continue
		}
		if agent.AgentSrcIntfAddr != nil {
			n.SetServiceIp(*agent.AgentSrcIntfAddr)
			logger.GetLogger().Debug("Service IP", "ip", n.GetServiceIp())
		}
		if agent.AgentHaSrcIntfAddr != nil {
			n.SetHaIp(*agent.AgentHaSrcIntfAddr)
			logger.GetLogger().Debug("HA IP", "ip", n.Ha.HaIp)
		}
	}
	return nil
}

func (n *Nxos) updtSasDpu(ctx context.Context, items *model.Cisco_NX_OSDevice_System_SasItems_DpuItems) error {

	if items.InstItems != nil {
		err := n.updtSasDpuInst(ctx, items.InstItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}

		logger.GetLogger().Debug("DPU Inst is updated")
		if n.Stage == StageDpu {
			n.Wait.In() <- WakeDpu
		}
	}

	if items.ExtItems != nil {
		err := n.updtSasDpuExt(ctx, items.ExtItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}

		// logger.GetLogger().Debug("DPU Ext is updated")
		if n.Stage == StageDpu {
			n.Wait.In() <- WakeDpu
		}
	}

	return nil
}

func (n *Nxos) updtSasDpuExt(ctx context.Context, items *model.Cisco_NX_OSDevice_System_SasItems_DpuItems_ExtItems) error {

	if items.InitState == model.Cisco_NX_OSDevice_Sas_InitStateE_inventory_done {
		n.DpuInvDone = true
		logger.GetLogger().Debug("DPU inventory done")
	}

	if items.NumDpus != nil {
		n.NumDpu = *items.NumDpus
		n.dpuListener.SetPeerGroupSize(n.NumDpu)
		logger.GetLogger().Debug("Number of DPUs", "dpu", n.NumDpu)

		for i := uint16(1); i <= n.NumDpu; i++ {
			err := n.setDpuPortRange(ctx, i)
			if err != nil {
				logger.GetLogger().Error("Fail to set port range", logfields.Error, err)
			}
		}
	}

	return nil
}

func (n *Nxos) updtSasDpuInst(ctx context.Context, items *model.Cisco_NX_OSDevice_System_SasItems_DpuItems_InstItems) error {

	for k, v := range items.InstList {
		if v == nil {
			logger.GetLogger().Debug("Inst missing for key", "key", k)
			continue
		}
		err := n.updtSasDpuInstInst(ctx, v)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}
	return nil
}

func (n *Nxos) updtSasDpuInstInst(ctx context.Context, list *model.Cisco_NX_OSDevice_System_SasItems_DpuItems_InstItems_InstList) error {

	if list.ModuleNum == nil {
		err := errors.New("missing DPU module number")
		logger.GetLogger().Error("", logfields.Error, err)
		return err
	}

	name := strconv.Itoa(int(*list.ModuleNum))
	logger.GetLogger().Debug("update DPU", "name", name)
	dpu, ok := n.Dpus[name]
	if !ok {
		dpu = Dpu{
			Name: name,
		}
	}
	if list.ExtItems != nil {
		err := n.updtSasDpuInstInstExt(ctx, list.ExtItems, &dpu)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}
	n.Dpus[name] = dpu

	fname := filepath.Join(rootVolatile, "dpu-"+name+".json")
	err := sanitizePath(fname, []string{rootVolatile})
	if err != nil {
		return errors.Join(err,
			fmt.Errorf("VRF name contains malicious path"))
	}
	n.store(ctx, fname, dpu)
	return nil
}

func (n *Nxos) updtSasDpuInstInstExt(_ context.Context, items *model.Cisco_NX_OSDevice_System_SasItems_DpuItems_InstItems_InstList_ExtItems, dpu *Dpu) error {
	// items.AsicState
	// items.BiosVer
	// items.DataPlaneErrorReason
	// items.GoldFwVer
	// items.HaBulkSyncState
	// items.HostIp
	// items.MacBase
	// items.MacNum
	// items.MainFwVer
	// items.OtherFwVer
	// items.PartNum
	// items.SerialNum
	if items.Ip != nil {
		dpu.Ip = *items.Ip
	}
	if items.Port != nil {
		dpu.Port = *items.Port
	}
	if items.MainFwVer != nil {
		dpu.Version = *items.MainFwVer
		n.DpuVersion = *items.MainFwVer
	}
	dpu.State = items.State
	return nil
}

func (n *Nxos) updtSasSvcSvcinstSvcInstanceHa(ctx context.Context, items *model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_HaItems) error {
	logger.GetLogger().Debug("updtSasSvcSvcinstSvcInstanceHa", "item", *items)

	n.SetHaConfigured(true)
	// hard coded enabled. ignore mo for now
	if items.AdminState == model.Cisco_NX_OSDevice_Sas_SvcHaAdminStateE_enabled {
		n.SetHaEnabled(true)
	} else if items.AdminState == model.Cisco_NX_OSDevice_Sas_SvcHaAdminStateE_disabled {
		n.SetHaEnabled(false)
	}
	logger.GetLogger().Debug("Ha Enabled updated", "enabled", n.GetHaEnabled())
	n.WaitHa.In() <- WakeHa

	if items.NxHaOperState == model.Cisco_NX_OSDevice_SasNxHaOperStateE_ha_ready {
		n.SetHaOperUp(true)
	} else if items.NxHaOperState == model.Cisco_NX_OSDevice_SasNxHaOperStateE_ha_not_initialized ||
		items.NxHaOperState == model.Cisco_NX_OSDevice_SasNxHaOperStateE_ha_disabled ||
		items.NxHaOperState == model.Cisco_NX_OSDevice_SasNxHaOperStateE_ha_ports_not_ready ||
		items.NxHaOperState == model.Cisco_NX_OSDevice_SasNxHaOperStateE_ha_ip_unavailable {
		n.SetHaOperUp(false)
	}
	logger.GetLogger().Debug("Ha OperUp updated", "oper", n.GetHaOperUp())
	n.WaitHa.In() <- WakeHa

	if items.PeerItems != nil {
		err := n.updtSasSvcSvcinstSvcInstanceHaPeer(ctx, items.PeerItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}

	n.store(ctx, haFname, n.Ha)
	return nil
}

func (n *Nxos) delHa(ctx context.Context) {
	logger.GetLogger().Debug("delete high availability")

	n.Ha.HaIp = ""
	n.SetHaConfigured(false)
	n.SetHaEnabled(false)
	n.SetHaOperUp(false)
	n.SetHaPeers(make(map[string]HaPeer))
	n.Ha.Adjacencies = make(map[string]HaAdj)
	n.Ha.Members = make(map[string]HaMbr)
	n.Ha.Alloc = make(map[string]HaAlloc)
	n.Ha.HaPeerSync = make(map[string]bool)
	n.Ha.Partners = make(map[string]struct{})
	n.Ha.NxStates.HaStateEpoch = 0
	n.Ha.NxStates.SvcStateEpoch = 0
	n.Ha.IsLeader = false
}

func (n *Nxos) delPeer(ctx context.Context, peer string) {
	logger.GetLogger().Debug("delete peer:", "peer", peer)

	n.Ha.Adjacencies = make(map[string]HaAdj)
	n.Ha.Members = make(map[string]HaMbr)
	n.SetHaPeers(make(map[string]HaPeer))
	n.Ha.Alloc = make(map[string]HaAlloc)
	n.Ha.HaPeerSync = make(map[string]bool)
	n.Ha.Partners = make(map[string]struct{})
	n.WaitHa.In() <- WakeHa
}

func (n *Nxos) updtSasSvcSvcinstSvcInstanceHaPeer(_ context.Context, items *model.Cisco_NX_OSDevice_System_SasItems_SvcItems_SvcinstItems_SvcInstanceList_HaItems_PeerItems) error {
	logger.GetLogger().Debug("updtSasSvcSvcinstSvcInstanceHaPeer", "item", *items)

	if len(items.HaPeerList) == 0 {
		logger.GetLogger().Debug("delete peer, adj and mbr")
		n.Ha.Adjacencies = make(map[string]HaAdj)
		n.Ha.Members = make(map[string]HaMbr)
		n.SetHaPeers(make(map[string]HaPeer))
		n.WaitHa.In() <- WakeHa
		return nil
	}

	var pip string
	var isOk bool
	for _, peer := range items.HaPeerList {
		if peer.IpAddr != nil {
			if pip == "" {
				pip = *peer.IpAddr
			} else {
				logger.GetLogger().Error("Unexpected number of peers")
				return nil
			}
			pip = *peer.IpAddr
			if peer.IpConfigState == model.Cisco_NX_OSDevice_Sas_PeerIpCfgStateE_success {
				isOk = true
			}
		}
	}
	if pip == "" {
		logger.GetLogger().Debug("No peer IP")
		return nil
	}

	logger.GetLogger().Debug("Add peer", "ip", pip)
	p, ok := n.GetHaPeer(pip)
	if ok {
		p.IpConfigOk = isOk
		n.SetHaPeer(pip, p)
	} else {
		n.SetHaPeers(make(map[string]HaPeer))
		n.SetHaPeer(pip, HaPeer{
			IpConfigOk: isOk,
		})
		n.Ha.HaPeerSync[pip] = false
		n.updateHaPeerSync()
	}

	n.WaitHa.In() <- WakeHa

	return nil
}

func (n *Nxos) updtSasVolatiledata(ctx context.Context, items *model.Cisco_NX_OSDevice_System_SasItems_VolatiledataItems) error {
	logger.GetLogger().Debug("updtSasVolatiledata")

	if items.AgentItems != nil {
		err := n.updtSasVolatiledataAgent(ctx, items.AgentItems)
		if err != nil {
			logger.GetLogger().Error("", logfields.Error, err)
			return err
		}
	}
	return nil
}

func (n *Nxos) updtSasGlobalpol(_ context.Context, items *model.Cisco_NX_OSDevice_System_SasItems_GlobalpolItems) error {
	logger.GetLogger().Debug("updtSasGlobalpol: LbMode", "mode", items.LbMode)

	if n.LbMode != items.LbMode {
		n.LbMode = items.LbMode
		logger.GetLogger().Debug("LbMode is changed")
	}
	return nil
}

func (n *Nxos) updtSasVolatiledataAgent(ctx context.Context, items *model.Cisco_NX_OSDevice_System_SasItems_VolatiledataItems_AgentItems) error {
	logger.GetLogger().Debug("updtSasVolatiledataAgent")

	for agent, data := range items.SasAgentDataList {
		if agent != "hypershield" {
			logger.GetLogger().Debug("Skip volatile data for agent", "name", agent)
			continue
		}
		if data.ConnToken != nil {
			// Set token in envToken var for agw to use
			// and save in ctrlr for restart use.
			logger.GetLogger().Info("ConnToken received", "len", len(*data.ConnToken))
			restartAgent, err := n.SetToken(ctx, *data.ConnToken)
			if err == nil {
				logger.GetLogger().Info("token updated")
				if n.Stage == StageNormal {
					if n.SkipReg && n.SkipRegReason == RegFailK8sAuth {
						n.unsetSkipReg(ctx, true)
					}
				} else {
					// Wake up anyone waiting for token
					logger.GetLogger().Debug("WakeToken")
					n.Wait.In() <- WakeToken
				}
				n.store(ctx, ctrlrFname, n.Ctrlr)
				if restartAgent {
					// Restart agent to use new token after cleaning up existing state
					// and deregistering if needed.
					n.ResetReg(ctx)
					n.GracefulRestartAgent(ctx, true)
				}
			} else {
				logger.GetLogger().Error("failed", logfields.Error, err)
			}
		}
	}
	return nil
}

func (n *Nxos) updtSwpkgs(ctx context.Context, items *model.Cisco_NX_OSDevice_System_SwpkgsItems) error {
	logger.GetLogger().Debug("updtSwpkgs")

	/*
		if items.RpmactionItems != nil {
			err := n.updtSwpkgsRpmaction(ctx, items.RpmactionItems)
			if err != nil {
				logger.GetLogger().Error("", logfields.Error, err)
				return err
			}
		}
	*/
	return nil
}

/*
func (n *Nxos) updtSwpkgsRpmaction(_ context.Context, items *model.Cisco_NX_OSDevice_System_SwpkgsItems_RpmactionItems) error {
	logger.GetLogger().Debug("updtSwpkgsRpmaction")

	if items.LastActionStatus != nil {
		logger.GetLogger().Debug("LastActionStatuss", "status", *items.LastActionStatus)
		status := *items.LastActionStatus
		if status != "SUCCESS" && status != "Adding" &&
			status != "Activating" && status != "Verifying package" &&
			status != "Verifying RPM" {
			n.Update.Status = status
		} else {
			logger.GetLogger().Debug("LastActionStatus ignored")
		}
	}
	return nil
}
*/

func (n *Nxos) doPinning(ctx context.Context, isBd bool, vb *VrfBd) {
	logger.GetLogger().Debug("doPinning: isBd", "bd", isBd)

	if vb.IsStatic {
		vb.DpuPinned = vb.Affinity
		logger.GetLogger().Debug("VRF/BD pinned to staticly", "name", vb.Name, "affinity", vb.DpuPinned)
	} else {
		hash := fnv1a([]byte(vb.Name))
		// dpu number starts from 1
		p := 1 + hash%uint64(n.NumDpu)
		vb.DpuPinned = uint16(p)
		logger.GetLogger().Debug("VRF/BD pinned to dynamically", "name", vb.Name, "affinity", vb.DpuPinned)
	}

	// TBD: when HA is introduced, get from ctrlr
	if !isBd {
		var gid uint16
		_, ok := n.Alloc.Gids[vb.Name]
		if !ok {
			if n.Ha.IsLeader {
				gid, ok = n.AllocPrev.Gids[vb.Name]
				if ok {
					n.Alloc.Gids[vb.Name] = gid
					n.GidsInUse[gid] = vb.Name
				} else {
					var found bool
					for _, alloc := range n.Ha.Alloc {
						gid, ok = alloc.Gids[vb.Name]
						if ok {
							_, ok = n.GidsInUse[gid]
							if !ok {
								n.Alloc.Gids[vb.Name] = gid
								n.GidsInUse[gid] = vb.Name
								found = true
								break
							}
						}
					}
					if !found {
						n.Alloc.Gids[vb.Name] = n.getGid(ctx, vb.Name)
					}
				}
			} else {
				var ok bool
				var gid uint16
				for peer, alloc := range n.Ha.Alloc {
					if peer < n.Ha.HaIp {
						continue
					}
					gid, ok = alloc.Gids[vb.Name]
					break
				}
				if !ok {
					gid, ok = n.AllocPrev.Gids[vb.Name]
				}
				if ok {
					n.Alloc.Gids[vb.Name] = gid
					n.GidsInUse[gid] = vb.Name
				} else {
					n.Alloc.Gids[vb.Name] = n.getGid(ctx, vb.Name)
				}
			}
		}
		logger.GetLogger().Debug("VRF uses global id", "name", vb.Name, "id", n.Alloc.Gids[vb.Name])
	}
	if isBd {
		n.Alloc.BdDpus[vb.Name] = vb.DpuPinned
	} else {
		n.Alloc.VrfDpus[vb.Name] = vb.DpuPinned
	}

	// persist the pinning
	n.store(ctx, allocFname, n.Alloc)
}

func (n *Nxos) progRepinning(ctx context.Context, isBd bool, vbs []VrfBd) error {
	if isBd {
		logger.GetLogger().Debug("program repinning for BDs", "bd", vbs)
	} else {
		logger.GetLogger().Debug("program repinning for VRFs", "bd", vbs)
	}

	if !n.IsLbModePinning(ctx) {
		logger.GetLogger().Debug("Unexpected repinning skipped")
		return nil
	}

	err := n.setFwPolicyState(ctx, isBd, vbs)
	if err != nil {
		logger.GetLogger().Error("Fail to set new fw policy state", logfields.Error, err)
		return err
	}

	if !isBd {
		for _, vb := range vbs {
			err = n.delDpuEndpointVrf(ctx, vb.Name)
			if err != nil {
				logger.GetLogger().Error("Fail to del service endpoint", logfields.Error, err)
			}
		}
		err = n.setDpuEndpointVrf(ctx, vbs)
	} else {
		err = n.setPolicyEnf(ctx, true, vbs)
	}
	if err != nil {
		logger.GetLogger().Error("Fail to re-set service endpoint", logfields.Error, err)
		return err
	}
	return nil
}

func (n *Nxos) getGid(ctx context.Context, vrf string) uint16 {
	// Non-leader in HA mode should use peer's GID to avoid collisions
	if n.haIsEnabled(ctx, false) && !n.Ha.IsLeader {
		for _, alloc := range n.Ha.Alloc {
			if gid, ok := alloc.Gids[vrf]; ok {
				logger.GetLogger().Debug("Non-leader using peer's GID", "vrf", vrf, "gid", gid)
				n.GidsInUse[gid] = vrf
				return gid
			}
		}
		// No peer GID found, will be reconciled later
		logger.GetLogger().Debug("Non-leader has no peer GID for VRF, will be reconciled", "vrf", vrf)
		return 0
	}

	// Original allocation logic for leader/non-HA
	begin := n.Alloc.Next
	gid := n.Alloc.Next
	for {
		// Check context cancellation
		select {
		case <-ctx.Done():
			logger.GetLogger().Info("Context canceled while allocating GID")
			return 0
		default:
		}

		_, ok := n.GidsInUse[gid]
		if ok {
			n.Alloc.Next++
			if n.Alloc.Next == 4095 {
				n.Alloc.Next = 10
			}
			if n.Alloc.Next == begin {
				logger.GetLogger().Error("Running out of global IDs")
				return 0
			}
			gid = n.Alloc.Next
		} else {
			n.GidsInUse[gid] = vrf
			return gid
		}
	}
}
