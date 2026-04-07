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
	"net"
	"sync/atomic"

	"google.golang.org/grpc"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"

	hastore "github.com/isovalent/hubble-fgs/pkg/nxos/store/ha"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/vlan"
	"github.com/isovalent/hubble-fgs/pkg/nxos/store/vrf"
	"github.com/isovalent/hubble-fgs/pkg/nxos/types"
	hav1 "github.com/isovalent/hubble-fgs/pkg/proto/ha/v1"
)

// Server defines the interface for the HA gRPC server.
type Server interface {
	Start(ctx context.Context, port uint16) error
	Stop() error
	IsRunning() bool
}

// ServerOption configures the HA server.
type ServerOption func(*server)

// WithHAStore sets the HA store for the server.
func WithHAStore(s hastore.Store) ServerOption {
	return func(srv *server) {
		srv.haStore = s
	}
}

// WithManager sets the HA manager for the server to delegate processing.
func WithManager(m Manager) ServerOption {
	return func(srv *server) {
		srv.manager = m
	}
}

// WithMemberInfoProvider sets the function to build local member info for responses.
func WithMemberInfoProvider(provider func() types.HAPeerMember) ServerOption {
	return func(srv *server) {
		srv.memberInfoProvider = provider
	}
}

// WithServerVRFStore sets the VRF store for the server to include VRF info in responses.
func WithServerVRFStore(s vrf.Store) ServerOption {
	return func(srv *server) {
		srv.vrfStore = s
	}
}

// WithServerVLANStore sets the VLAN store for the server to include VLAN info in responses.
func WithServerVLANStore(s vlan.Store) ServerOption {
	return func(srv *server) {
		srv.vlanStore = s
	}
}

// WithServerReconciler sets the reconciler for the server to reconcile peer data on incoming requests.
func WithServerReconciler(r *Reconciler) ServerOption {
	return func(srv *server) {
		srv.reconciler = r
	}
}

// server implements the Server interface and the gRPC Ha service.
type server struct {
	hav1.UnimplementedHaServer
	grpcServer         *grpc.Server
	haStore            hastore.Store
	manager            Manager
	memberInfoProvider func() types.HAPeerMember
	vrfStore           vrf.Store
	vlanStore          vlan.Store
	reconciler         *Reconciler
	running            atomic.Bool
}

// NewServer creates a new HA server with the given options.
func NewServer(opts ...ServerOption) Server {
	s := &server{}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Start starts the HA gRPC server. It blocks until the server stops or an
// error occurs. The caller is responsible for calling Stop (e.g. on context
// cancellation) to unblock Serve.
func (s *server) Start(ctx context.Context, port uint16) error {
	conn, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		logger.GetLogger().Error("HA server failed to listen", logfields.Error, err, "port", port)
		return err
	}

	s.grpcServer = grpc.NewServer()
	hav1.RegisterHaServer(s.grpcServer, s)
	s.running.Store(true)

	logger.GetLogger().Info("HA server starting", "port", port)

	err = s.grpcServer.Serve(conn)
	s.running.Store(false)
	if err != nil {
		logger.GetLogger().Error("HA server failed to serve", logfields.Error, err)
		return err
	}

	return nil
}

// Stop gracefully stops the HA server.
func (s *server) Stop() error {
	if s.grpcServer != nil {
		logger.GetLogger().Info("HA server stopping")
		s.grpcServer.GracefulStop()
		s.running.Store(false)
	}
	return nil
}

// IsRunning returns true if the server is currently running.
func (s *server) IsRunning() bool {
	return s.running.Load()
}

// Adjacency implements the Ha gRPC service Adjacency method.
func (s *server) Adjacency(ctx context.Context, req *hav1.AdjRequest) (*hav1.AdjResponse, error) {
	logger.GetLogger().Debug("HA server received Adjacency request", "peer", req.HaIp, "mbr", req.MbrInfo)

	if s.haStore == nil {
		logger.GetLogger().Error("HA store not configured")
		return &hav1.AdjResponse{
			Status:  hav1.ADJ_RESPONSE_STATUS_ADJ_FAILURE,
			Details: "HA store not configured",
		}, nil
	}

	// Check if peer is known
	_, peerKnown := s.haStore.Peer(req.HaIp)
	if !peerKnown {
		logger.GetLogger().Debug("HA server received request from unexpected peer", "peer", req.HaIp)
		return &hav1.AdjResponse{
			Status:  hav1.ADJ_RESPONSE_STATUS_ADJ_FAILURE,
			Details: "Unexpected peer",
		}, nil
	}

	// Check for NO_HA (intentional HA removal).
	// Clear peer runtime state but keep peer in config so the adjacency loop
	// can reconnect when HA is re-enabled on the peer.
	if req.MbrInfo != nil && req.MbrInfo.HaInfo != nil && req.MbrInfo.HaInfo.Ha == hav1.HA_STATE_NO_HA {
		logger.GetLogger().Info("Peer signaled HA removal (NO_HA state)", "peer", req.HaIp)
		if s.manager != nil {
			s.manager.HandleRemoval(ctx, req.HaIp)
		}
		responseMbrInfo := s.buildLocalMbrInfo(req.HaIp)
		return &hav1.AdjResponse{
			Status:  hav1.ADJ_RESPONSE_STATUS_ADJ_SUCCESS,
			Details: "HA removal acknowledged",
			MbrInfo: responseMbrInfo,
		}, nil
	}

	// Process member info through the manager and check validation result.
	var isDel bool
	var reason string
	if req.MbrInfo != nil && s.manager != nil {
		memberInfo := convertMbrInfoToPeerMember(req.MbrInfo)
		isDel, reason = s.manager.ProcessMemberInfo(ctx, req.HaIp, memberInfo)
	}

	// Process HaInfo from the adjacency request to update peer svc/ha state
	// and leader status, and trigger leader election immediately.
	if req.MbrInfo != nil && req.MbrInfo.HaInfo != nil && s.manager != nil {
		s.manager.ProcessHaInfo(ctx, req.HaIp, req.MbrInfo.HaInfo)
	}

	// Reconcile VRF GIDs from the incoming request.
	if req.MbrInfo != nil && s.reconciler != nil {
		var lbMode string
		if s.memberInfoProvider != nil {
			lbMode = s.memberInfoProvider().LbMode
		}
		ok, err := s.reconciler.Reconcile(ctx, req.HaIp, req.MbrInfo, lbMode)
		if err != nil {
			logger.GetLogger().Warn("HA server reconciliation failed", "peer", req.HaIp, "error", err)
		}
		if s.haStore != nil {
			s.haStore.UpdatePeerMemberCriterion(ctx, req.HaIp, types.HACritPeerVrfGid, ok)
		}
	}

	// Build response with local member info.
	responseMbrInfo := s.buildLocalMbrInfo(req.HaIp)

	// Return ADJ_FAILURE on membership/policy validation failures so the peer
	// can fast-path failure detection. Still include local MbrInfo in the
	// response so the peer can update its criteria.
	if isDel {
		return &hav1.AdjResponse{
			Status:  hav1.ADJ_RESPONSE_STATUS_ADJ_FAILURE,
			Details: reason,
			MbrInfo: responseMbrInfo,
		}, nil
	}

	return &hav1.AdjResponse{
		Status:  hav1.ADJ_RESPONSE_STATUS_ADJ_SUCCESS,
		Details: "KeepAlive successful",
		MbrInfo: responseMbrInfo,
	}, nil
}

// Notify implements the Ha gRPC service Notify method.
func (s *server) Notify(ctx context.Context, req *hav1.NotifyRequest) (*hav1.NotifyResponse, error) {
	logger.GetLogger().Debug("HA server received Notify", "peer", req.HaIp, "haInfo", req.HaInfo)

	if s.haStore == nil {
		return &hav1.NotifyResponse{
			Status:  hav1.ADJ_RESPONSE_STATUS_ADJ_FAILURE,
			Details: "HA store not configured",
		}, nil
	}

	_, peerKnown := s.haStore.Peer(req.HaIp)
	if !peerKnown {
		return &hav1.NotifyResponse{
			Status:  hav1.ADJ_RESPONSE_STATUS_ADJ_FAILURE,
			Details: "Unexpected peer",
		}, nil
	}

	if s.manager != nil {
		if req.HaInfo != nil {
			// Process incoming HaInfo for standby injection/removal.
			s.manager.ProcessHaInfo(ctx, req.HaIp, req.HaInfo)
		} else {
			// Legacy: no HaInfo means adj failure notify.
			s.manager.HandleAdjFailureNotify(ctx, req.HaIp, "peer notify")
		}
	}

	// Build response with local HaInfo so peer learns our state immediately.
	var responseHaInfo *hav1.HaInfo
	if s.haStore != nil {
		responseHaInfo = buildLocalHaInfoFromStore(s.haStore)
	}

	return &hav1.NotifyResponse{
		Status: hav1.ADJ_RESPONSE_STATUS_ADJ_SUCCESS,
		HaInfo: responseHaInfo,
	}, nil
}

// buildLocalMbrInfo builds the local member info for adjacency responses.
// peerIP is the requesting peer's IP, used to include per-peer debug flags.
func (s *server) buildLocalMbrInfo(peerIP string) *hav1.MbrInfo {
	var mbrInfo *hav1.MbrInfo
	if s.memberInfoProvider != nil {
		info := s.memberInfoProvider()
		mbrInfo = convertPeerMemberToMbrInfo(info)
	} else {
		mbrInfo = &hav1.MbrInfo{}
	}

	// Override HaInfo from the haStore to ensure IsLeader is accurately reflected.
	// convertPeerMemberToMbrInfo builds HaInfo from HAPeerMember which has no IsLeader
	// field, so without this the adjacency response always carries IsLeader=false —
	// causing the initiator to incorrectly clear the peer's leader status and
	// potentially elect itself even when the peer is the legitimate leader.
	if s.haStore != nil {
		mbrInfo.HaInfo = buildLocalHaInfoFromStore(s.haStore)
	}

	// Include VRF and VLAN info so the peer can reconcile
	if s.vrfStore != nil {
		mbrInfo.VrfInfo = BuildLocalVRFInfo(s.vrfStore)
	}
	if s.vlanStore != nil {
		mbrInfo.VlanInfo = BuildLocalVLANInfo(s.vlanStore)
		mbrInfo.VlanIdRanges = BuildLocalVLANIdRanges(s.vlanStore)
	}

	// Include local debug override flags for this peer.
	if s.haStore != nil && peerIP != "" {
		if peerState, ok := s.haStore.Peer(peerIP); ok {
			if val, exists := peerState.MemberCriteria[types.HACritDebugMembershipFail]; exists && !val {
				mbrInfo.DebugMembershipFail = true
			}
			if val, exists := peerState.AdjacencyCriteria[types.HACritDebugAdjacencyFail]; exists && !val {
				mbrInfo.DebugAdjacencyFail = true
			}
		}
	}

	return mbrInfo
}

// haStateToProto converts a types.HAState* string to the proto enum.
func haStateToProto(s string) hav1.HA_STATE {
	switch s {
	case types.HAStateReady:
		return hav1.HA_STATE_HA_READY
	case types.HAStateDegraded:
		return hav1.HA_STATE_HA_DEGRADED
	case types.HAStateSwitchover:
		return hav1.HA_STATE_HA_SWITCHOVER
	case types.HAStateTakeover:
		return hav1.HA_STATE_HA_TAKEOVER
	case types.HAStateUnavailable:
		return hav1.HA_STATE_HA_UNAVAILABLE
	default:
		return hav1.HA_STATE_HA_NOTREADY
	}
}

// protoToHaState converts a proto HA_STATE enum to a types.HAState* string.
// Returns "" for unrecognised values.
func protoToHaState(p hav1.HA_STATE) string {
	switch p {
	case hav1.HA_STATE_HA_READY:
		return types.HAStateReady
	case hav1.HA_STATE_HA_DEGRADED:
		return types.HAStateDegraded
	case hav1.HA_STATE_HA_NOTREADY:
		return types.HAStateNotReady
	case hav1.HA_STATE_HA_SWITCHOVER:
		return types.HAStateSwitchover
	case hav1.HA_STATE_HA_TAKEOVER:
		return types.HAStateTakeover
	case hav1.HA_STATE_HA_UNAVAILABLE:
		return types.HAStateUnavailable
	default:
		return ""
	}
}

// buildLocalHaInfoFromStore builds a HaInfo proto from the current HA store local state.
func buildLocalHaInfoFromStore(store hastore.Reader) *hav1.HaInfo {
	local := store.Local()
	svc := hav1.LOCAL_SVC_STATE_LOCAL_SVC_FAILURE
	if local.CriteriaMet && !local.CriteriaRecoveryPending {
		svc = hav1.LOCAL_SVC_STATE_LOCAL_SVC_SUCCESS
	}
	return &hav1.HaInfo{
		LocalSvcState: svc,
		Ha:            haStateToProto(local.HaState),
		IsLeader:      store.IsLeader(),
	}
}

// convertMbrInfoToPeerMember converts proto MbrInfo to types.HAPeerMember.
func convertMbrInfoToPeerMember(info *hav1.MbrInfo) types.HAPeerMember {
	if info == nil {
		return types.HAPeerMember{}
	}

	member := types.HAPeerMember{}
	if info.SysInfo != nil {
		member.SerialNum = info.SysInfo.SerNum
		member.Model = info.SysInfo.Model
		member.SWVersion = info.SysInfo.SwVer
		member.CPAVersion = info.SysInfo.Cpa
		member.LbMode = info.SysInfo.LbMode
		for _, dpu := range info.SysInfo.Dpus {
			member.DPUs = append(member.DPUs, types.DPUVersion{
				Name:    dpu.Name,
				Version: dpu.Version,
			})
		}
	}
	if info.PolInfo != nil {
		member.PolicyRev = info.PolInfo.Revision
		member.PolicyCheck = info.PolInfo.Watching
	}
	if info.HaInfo != nil {
		member.HaState = protoToHaState(info.HaInfo.Ha)
		switch info.HaInfo.GetLocalSvcState() {
		case hav1.LOCAL_SVC_STATE_LOCAL_SVC_SUCCESS:
			member.Service = types.SvcStateSuccess
		case hav1.LOCAL_SVC_STATE_LOCAL_SVC_FAILURE:
			member.Service = types.SvcStateFailure
		}
	}

	// Debug overrides propagated from peer.
	member.DebugMembershipFail = info.DebugMembershipFail
	member.DebugAdjacencyFail = info.DebugAdjacencyFail

	return member
}

// convertPeerMemberToMbrInfo converts types.HAPeerMember to proto MbrInfo.
func convertPeerMemberToMbrInfo(info types.HAPeerMember) *hav1.MbrInfo {
	mbrInfo := &hav1.MbrInfo{
		SysInfo: &hav1.SysInfo{
			SerNum: info.SerialNum,
			Model:  info.Model,
			SwVer:  info.SWVersion,
			Cpa:    info.CPAVersion,
			LbMode: info.LbMode,
		},
		PolInfo: &hav1.PolInfo{
			Revision: info.PolicyRev,
			Watching: info.PolicyCheck,
		},
	}
	for _, dpu := range info.DPUs {
		mbrInfo.SysInfo.Dpus = append(mbrInfo.SysInfo.Dpus, &hav1.DpuVer{
			Name:    dpu.Name,
			Version: dpu.Version,
		})
	}

	// Set HA info
	svc := hav1.LOCAL_SVC_STATE_LOCAL_SVC_FAILURE
	if info.Service == types.SvcStateSuccess {
		svc = hav1.LOCAL_SVC_STATE_LOCAL_SVC_SUCCESS
	}
	mbrInfo.HaInfo = &hav1.HaInfo{
		LocalSvcState: svc,
		Ha:            haStateToProto(info.HaState),
	}

	// Debug overrides.
	mbrInfo.DebugMembershipFail = info.DebugMembershipFail
	mbrInfo.DebugAdjacencyFail = info.DebugAdjacencyFail

	return mbrInfo
}
