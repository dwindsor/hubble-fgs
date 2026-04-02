// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package ha

import (
	"context"
	"fmt"

	"github.com/cilium/tetragon/pkg/logger"

	hastore "github.com/isovalent/hubble-fgs/pkg/nxos/store/ha"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

// LocalDeviceInfo contains information about the local device for member validation.
type LocalDeviceInfo struct {
	SerialNum  string
	Model      string
	SWVersion  string
	CPAVersion string
	LbMode     string
	DPUs       map[string]string // name → version
}

// Validator validates HA member info and manages partner state.
type Validator struct {
	haStore    hastore.Store
	deviceInfo func() LocalDeviceInfo
}

// NewValidator creates a new validator.
func NewValidator(store hastore.Store, deviceInfoProvider func() LocalDeviceInfo) *Validator {
	return &Validator{
		haStore:    store,
		deviceInfo: deviceInfoProvider,
	}
}

// ValidateMemberInfo validates peer member info against local device info.
// Returns (isDel, isHardFailure, reason):
//   - isDel: true if the peer should be marked as a failed partner
//   - isHardFailure: true if the failure is a membership/required-criteria failure
//     (model, version, DPU mismatch). False for soft failures (peer service failure,
//     policy mismatch) which should not contaminate membership criteria.
//   - reason: human-readable description of the failure
func (v *Validator) ValidateMemberInfo(ctx context.Context, peer string, info types.HAPeerMember) (bool, bool, string) {
	logger.GetLogger().Debug("ValidateMemberInfo", "peer", peer)

	local := v.deviceInfo()

	var isDel bool
	var isHardFailure bool
	var reason string

	if info.Model == "" || info.SWVersion == "" || info.LbMode == "" {
		isDel = true
		isHardFailure = true
		reason = "missing system info"
	} else if info.Model != local.Model {
		isDel = true
		isHardFailure = true
		reason = fmt.Sprintf("model mismatch: peer=%s local=%s", info.Model, local.Model)
	} else if info.SWVersion != local.SWVersion {
		isDel = true
		isHardFailure = true
		reason = fmt.Sprintf("NxOS version mismatch: peer=%s local=%s", info.SWVersion, local.SWVersion)
	} else if info.CPAVersion != local.CPAVersion {
		isDel = true
		isHardFailure = true
		reason = fmt.Sprintf("CPA version mismatch: peer=%s local=%s", info.CPAVersion, local.CPAVersion)
	} else if len(info.DPUs) != len(local.DPUs) {
		isDel = true
		isHardFailure = true
		reason = fmt.Sprintf("DPU count mismatch: peer=%d local=%d", len(info.DPUs), len(local.DPUs))
	} else if info.LbMode != local.LbMode {
		isDel = true
		isHardFailure = true
		reason = fmt.Sprintf("LB mode mismatch: peer=%s local=%s", info.LbMode, local.LbMode)
	} else if info.Service == types.SvcStateFailure {
		isDel = true
		// Soft failure: peer service failure should NOT mark membership as failed.
		// It produces ha-unavailable (tier 1) via the peerSvcReady check in computePeerHaState.
		reason = "peer service failure"
	} else {
		// Check DPU versions
		for _, peerDPU := range info.DPUs {
			localVer, ok := local.DPUs[peerDPU.Name]
			if !ok {
				isDel = true
				isHardFailure = true
				reason = fmt.Sprintf("DPU not found: %s", peerDPU.Name)
				break
			}
			if localVer != peerDPU.Version {
				isDel = true
				isHardFailure = true
				reason = fmt.Sprintf("DPU version mismatch: peer=%s local=%s for %s",
					peerDPU.Version, localVer, peerDPU.Name)
				break
			}
		}
	}

	// Check policy revision mismatch while checking policy.
	// This is a soft failure — does not affect membership criteria.
	if !isDel {
		localInfo := v.haStore.Local()
		if localInfo.PolicyCheck && localInfo.PolicyRev != info.PolicyRev {
			isDel = true
			reason = fmt.Sprintf("policy revision mismatch while checking: peer=%s local=%s",
				info.PolicyRev, localInfo.PolicyRev)
		}
	}

	return isDel, isHardFailure, reason
}

// ComputePeerPolicy computes whether the peer's policy is OK based on policy check state.
func (v *Validator) ComputePeerPolicy(policyCheck bool, localPolRev string, peerInfo types.HAPeerMember) bool {
	if policyCheck {
		return localPolRev == peerInfo.PolicyRev
	}
	// Not checking policy
	if peerInfo.PolicyCheck && localPolRev == peerInfo.PolicyRev {
		return true
	}
	if !peerInfo.PolicyCheck && localPolRev >= peerInfo.PolicyRev {
		return true
	}
	return false
}

// UpdatePartner updates the peer svc state to exactly reflect the peer's reported local service state.
func (v *Validator) UpdatePartner(ctx context.Context, peer string, info types.HAPeerMember) {
	logger.GetLogger().Debug("UpdatePartner", "peer", peer, "service", info.Service)

	switch info.Service {
	case types.SvcStateSuccess:
		v.haStore.UpdatePeerSvcState(ctx, peer, types.SvcStateSuccess, types.NewReasonString("peer service ready"))
	case types.SvcStateFailure:
		v.haStore.UpdatePeerSvcState(ctx, peer, types.SvcStateFailure, types.NewReasonString("peer service not-ready"))
	default:
		v.haStore.UpdatePeerSvcState(ctx, peer, types.SvcStateUnknown, types.NewReasonString("peer service unknown"))
	}
}
