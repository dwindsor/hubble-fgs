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

	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
)

// Reader provides read-only access to HA data.
type Reader interface {
	Enabled() string
	SwitchState() string
	HaIP() string

	// Local sub-object access (returns deep copy via Copy())
	Local() types.HALocalState
	IsLeader() bool
	IsServiceFunctional() bool

	// Peer sub-object access (returns deep copies via Copy())
	Peer(ip string) (types.HAPeerState, bool)
	AllPeers() map[string]types.HAPeerState
	PeerIPs() []string
	AnyPeerAdjacencyCriteriaOk() bool
	AnyPeerMemberCriteriaFail() bool
	AnyPeerInHaReady() bool
}

// Watcher allows subscribing to HA changes.
type Watcher interface {
	Watch(callback func(event Event)) (unsubscribe func())
}

// Store provides full access to HA data.
type Store interface {
	Reader
	Watcher

	// Top-level state
	SetEnabled(ctx context.Context, state string)
	SetSwitchState(ctx context.Context, state string)
	SetHaIP(ctx context.Context, ip string)

	// Local sub-object mutations
	SetLocal(ctx context.Context, local types.HALocalState)
	SetLeader(ctx context.Context, isLeader bool)
	UpdateLocalCriterion(ctx context.Context, crit types.HACriterion, val bool)
	SetLocalDerivedStates(ctx context.Context, haState, svcState string, haReason, svcReason types.ReasonString)
	SetLocalPolicyRevision(ctx context.Context, rev string)
	SetLocalPolicyCheck(ctx context.Context, check bool)
	SetLocalAdjacencyReached(ctx context.Context, reached bool)
	SetLocalCriteriaMet(ctx context.Context, local types.HALocalState)

	// Peer sub-object mutations
	SetPeer(ctx context.Context, ip string, info types.HAPeerState)
	RemovePeer(ctx context.Context, ip string)
	UpdatePeerMemberCriterion(ctx context.Context, ip string, crit types.HACriterion, val bool)
	UpdatePeerAdjacencyCriterion(ctx context.Context, ip string, crit types.HACriterion, val bool)
	UpdatePeerMember(ctx context.Context, ip string, member *types.HAPeerMember)
	UpdatePeerSvcState(ctx context.Context, ip string, svcState string, reason types.ReasonString)
	UpdatePeerAdjacency(ctx context.Context, ip string, connected bool, epoch int64)
	UpdatePeerDPUStatuses(ctx context.Context, ip string, statuses map[string]types.DPUHAStatus)

	// gNMI integration
	SetGnmiHandler(handler gnmi.GnmiHandler)
	HandleGnmiNotification(ctx context.Context, path string, update *gnmiproto.Update, isDelete bool)

	// gNMI SET
	SetLocalHaState(ctx context.Context, state string, reason types.ReasonString) error
	SetLocalHaStateToNotReady(ctx context.Context, reason types.ReasonString) error
	SetLocalSvcState(ctx context.Context, state string, reason types.ReasonString) error
	SetLocalSvcStateToFailure(ctx context.Context, reason types.ReasonString) error
	SetRemoteMbrState(ctx context.Context, peerIP string, state string, reason types.ReasonString) error
	SetRemoteSvcState(ctx context.Context, peerIP string, state string, reason types.ReasonString) error
	SetRemoteStatesAdjDown(ctx context.Context, peerIP string) error
}
