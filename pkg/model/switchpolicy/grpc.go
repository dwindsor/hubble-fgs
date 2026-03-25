// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package switchpolicy

import (
	"context"
	"fmt"
	"io"

	"google.golang.org/grpc"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"github.com/isovalent/hubble-fgs/pkg/config"
	"github.com/isovalent/hubble-fgs/pkg/config/library"
)

type AGWServer struct {
	v1alpha.UnimplementedL3L4NetworkPolicyServiceServer

	dpuListener *DPUListener
}

func (s *AGWServer) ReportStatus(_ context.Context, req *v1alpha.ReportStatusRequest) (*v1alpha.ReportStatusResponse, error) {
	// Validate AgentUid is not empty
	if req.Status != nil && req.Status.AgentUid == "" {
		logger.GetLogger().Error("Rejecting DPU status report with empty AgentUid")
		return nil, fmt.Errorf("AgentUid cannot be empty")
	}

	status := reportRequestToDPU(req)
	s.dpuListener.ReportStatus(status)
	return &v1alpha.ReportStatusResponse{}, nil
}

func (s *AGWServer) Streaml3L4NetworkPolicy(req *v1alpha.Streaml3L4NetworkPolicyRequest, stream grpc.ServerStreamingServer[v1alpha.Streaml3L4NetworkPolicyResponse]) error {
	// Validate AgentUid is not empty
	if req.AgentUid == "" {
		logger.GetLogger().Error("Rejecting DPU connection with empty AgentUid")
		return fmt.Errorf("AgentUid cannot be empty")
	}

	initializedPeer := func() *peer {
		s.dpuListener.mtx.Lock()
		defer s.dpuListener.mtx.Unlock()
		peer := s.dpuListener.addPeerLocked(req.AgentUid)
		// Always create a fresh reconnect channel for this stream so the
		// handler always listens on a known-empty channel. StateCheck
		// signals reconnect via send (not close), so we don't need to
		// preserve any previous channel state.
		peer.polReconnectCh = make(chan struct{}, 1)
		peer.syncFailCount.Store(0)   // Resetting sync count
		peer.polReconnectCount.Add(1) // Increment policy reconnect counter

		// The peer on reconnect needs to diff its current set with this set
		// and create the valid policy otherwise subsequent policy hash checks will
		// fail. If the peer builds on top of its current state without this check
		// then we could potentially leave policy rules orphaned in the peers
		// datapath.

		// This is still not perfect for similar reasons as mentioned in
		// the comment in SubmitUpdateToDPU, but at least it works most of the time.
		for _, r := range s.dpuListener.ruleSet {
			policyRule := &DPUPolicyRule{
				Oper:   v1alpha.PolicyOperation_POLICY_OPERATION_UPSERT,
				Policy: r,
			}
			resp := dpuRuleToResponse(policyRule)
			err := stream.Send(resp)
			if err != nil {
				logger.GetLogger().Warn("Client send failed", "clientID", peer.uid, logfields.Error, err)
				return nil
			}
		}
		return peer
	}()

	if initializedPeer == nil {
		return nil
	}

	for {
		select {
		case <-s.dpuListener.ctx.Done():
			logger.GetLogger().Info("Client connection lost", "clientID", initializedPeer.uid)
			return nil
		case <-initializedPeer.polReconnectCh:
			logger.GetLogger().Info("Forcing client reconnect due to timeout", "clientID", initializedPeer.uid)
			return nil
		case rule := <-initializedPeer.polCh:
			resp := dpuRuleToResponse(rule)
			err := stream.Send(resp)
			if err != nil {
				logger.GetLogger().Error("failed to send message", logfields.Error, err)
				return err
			}
			logger.GetLogger().Debug("Pushed policy to client", "clientID", initializedPeer.uid, "policy", *rule)
		}
	}
}

func (s *AGWServer) StreamDatapathConfig(req *v1alpha.StreamDatapathConfigRequest, stream grpc.ServerStreamingServer[v1alpha.StreamDatapathConfigResponse]) error {
	// Validate AgentUid is not empty
	if req.AgentUid == "" {
		logger.GetLogger().Error("Rejecting DPU config conn with empty AgentUid")
		return fmt.Errorf("AgentUid cannot be empty")
	}

	initializedPeer := func() *peer {
		s.dpuListener.mtx.Lock()
		defer s.dpuListener.mtx.Unlock()
		peer := s.dpuListener.addPeerLocked(req.AgentUid)
		peer.cfgReconnectCount.Add(1) // Increment config reconnect counter

		// Clear cfgSet on reconnect so the DPU gets a full config resync.
		// The DPU may have restarted and lost all state, so we cannot
		// assume it still has the configs from the previous connection.
		peer.cfgSet = make(map[v1alpha.ConfigType]*v1alpha.ConfigObject)

		// Config sync start
		logger.GetLogger().Info("sync peer config start", "peer", peer.uid)

		// Diffing the peer's config set with the current latest config set to be able
		// to pass down changes to the peer that just connected.
		configList := library.GetRepository().GetConfigObjects()
		adds, removes := config.DiffConfigSets(peer.cfgSet, configList)

		// Making sure that the dpu config object is passed down first, as it sets
		// some of the service configuration that is required for other configs.
		dpuConfigObj, ok := adds[v1alpha.ConfigType_CONFIG_TYPE_DPU]
		if ok {
			dpuCfg, err := getPerDpuConfig(dpuConfigObj.GetConfigDpu(), peer.uid, s.dpuListener.peerGroupSize)
			if err != nil {
				logger.GetLogger().Error("failed to pass down dpu config to dpu", logfields.Error, err)
			} else {
				obj := &v1alpha.ConfigObject{
					Type:   v1alpha.ConfigType_CONFIG_TYPE_DPU,
					Config: &v1alpha.ConfigObject_ConfigDpu{ConfigDpu: dpuCfg},
				}
				peer.cfgSet[v1alpha.ConfigType_CONFIG_TYPE_DPU] = obj
				resp := v1alpha.StreamDatapathConfigResponse{
					Oper:   v1alpha.ConfigOperation_CONFIG_OPERATION_UPSERT,
					Config: obj,
				}
				err := stream.Send(&resp)
				if err != nil {
					logger.GetLogger().Warn("Client send failed", "clientID", peer.uid, logfields.Error, err)
					return nil
				}
			}
			delete(adds, v1alpha.ConfigType_CONFIG_TYPE_DPU)
		}

		// Handle HA config separately (similar to DPU config) since it requires per-DPU transformation
		haConfigObj, ok := adds[v1alpha.ConfigType_CONFIG_TYPE_HA]
		if ok {
			haCfg, err := getPerDpuHaConfig(haConfigObj.GetConfigHa(), peer.uid, s.dpuListener.peerGroupSize)
			if err != nil {
				logger.GetLogger().Error("failed to pass down ha config to dpu", logfields.Error, err)
			} else {
				obj := &v1alpha.ConfigObject{
					Type:   v1alpha.ConfigType_CONFIG_TYPE_HA,
					Source: haConfigObj.Source,
					Config: &v1alpha.ConfigObject_ConfigHa{ConfigHa: haCfg},
				}
				peer.cfgSet[v1alpha.ConfigType_CONFIG_TYPE_HA] = obj
				resp := v1alpha.StreamDatapathConfigResponse{
					Oper:   v1alpha.ConfigOperation_CONFIG_OPERATION_UPSERT,
					Config: obj,
				}
				err := stream.Send(&resp)
				if err != nil {
					logger.GetLogger().Warn("Client send failed", "clientID", peer.uid, logfields.Error, err)
					return nil
				}
			}
			delete(adds, v1alpha.ConfigType_CONFIG_TYPE_HA)
		}

		// Iterating through all the adds and deletes and passing the messages to the DPU peer.
		for typ, obj := range adds {
			peer.cfgSet[typ] = obj
			resp := v1alpha.StreamDatapathConfigResponse{
				Oper:   v1alpha.ConfigOperation_CONFIG_OPERATION_UPSERT,
				Config: obj,
			}
			err := stream.Send(&resp)
			if err != nil {
				logger.GetLogger().Warn("Client send config upsert failed", "clientID", peer.uid, logfields.Error, err)
				return nil
			}
		}
		for typ, obj := range removes {
			peer.cfgSet[typ] = obj
			resp := v1alpha.StreamDatapathConfigResponse{
				Oper:   v1alpha.ConfigOperation_CONFIG_OPERATION_DELETE,
				Config: obj,
			}
			err := stream.Send(&resp)
			if err != nil {
				logger.GetLogger().Warn("Client send config delete failed", "clientID", peer.uid, logfields.Error, err)
				return nil
			}
		}

		// Config sync complete
		logger.GetLogger().Info("sync peer config complete", "peer", peer.uid)

		return peer
	}()

	if initializedPeer == nil {
		return nil
	}

	for {
		select {
		case <-s.dpuListener.ctx.Done():
			logger.GetLogger().Info("Client connection lost", "clientID", initializedPeer.uid)
			return nil
		case <-initializedPeer.cfgReconnectCh:
			logger.GetLogger().Info("Forcing client config reconnect due to timeout", "clientID", initializedPeer.uid)
			return nil
		case resp := <-initializedPeer.cfgCh:
			// Updating cfgSet to save desired config state
			// This is the only thread that writes to the CfgSet for this peer
			switch resp.Oper {
			case v1alpha.ConfigOperation_CONFIG_OPERATION_UNSPECIFIED:
				logger.GetLogger().Warn("Unspecified operation, passing message through to datapath")
			case v1alpha.ConfigOperation_CONFIG_OPERATION_UPSERT:
				initializedPeer.cfgSet[v1alpha.ConfigType(resp.Config.Type)] = resp.Config
			case v1alpha.ConfigOperation_CONFIG_OPERATION_DELETE:
				delete(initializedPeer.cfgSet, v1alpha.ConfigType(resp.Config.Type))
			default:
				logger.GetLogger().Error("Invalid operation, failed to send to datapath")
				continue
			}

			err := stream.Send(resp)
			if err != nil {
				logger.GetLogger().Warn("Client send failed", "clientID", initializedPeer.uid, logfields.Error, err)
				return nil
			}
			logger.GetLogger().Debug("Pushed config to client", "clientID", initializedPeer.uid, "config", resp)
		}
	}
}

func (s *AGWServer) StreamEvents(stream grpc.ClientStreamingServer[v1alpha.StreamEventsRequest, v1alpha.StreamEventsResponse]) error {
	var initializedPeer *peer

	for {
		req, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				if initializedPeer != nil {
					logger.GetLogger().Info("Event stream closed", "clientID", initializedPeer.uid)
				}
				return stream.SendAndClose(&v1alpha.StreamEventsResponse{})
			}
			logger.GetLogger().Error("Failed to receive event stream", logfields.Error, err)
			return err
		}

		// Initialize peer on first message
		if initializedPeer == nil && len(req.Events) > 0 {
			agentUid := req.Events[0].AgentUid
			if agentUid == "" {
				logger.GetLogger().Error("Rejecting event stream with empty AgentUid")
				return fmt.Errorf("AgentUid cannot be empty")
			}

			initializedPeer = func() *peer {
				s.dpuListener.mtx.Lock()
				defer s.dpuListener.mtx.Unlock()
				peer := s.dpuListener.addPeerLocked(agentUid)

				if haEventHandler != nil {
					haEventHandler.RegisterDpu(stream.Context(), agentUid)
				}

				logger.GetLogger().Info("Event stream peer connected", "clientID", peer.uid)
				return peer
			}()

			if initializedPeer == nil {
				return nil
			}
		}

		for _, event := range req.Events {
			switch e := event.GetEvent().(type) {
			case *v1alpha.StreamEvent_Rule:
				// Log the policy rule event
				logger.GetLogger().Debug("agw server: Received policy rule event",
					"agentUid", event.AgentUid,
					"ruleName", e.Rule.RuleName,
					"policyName", e.Rule.PolicyName,
					"isSuccess", e.Rule.IsSuccess,
					"message", e.Rule.ErrorMessage,
					"errorCode", e.Rule.Error,
				)
				// Process policy rule event through the DPU listener's handler
				if handler := s.dpuListener.GetPolicyStatusHandler(); handler != nil {
					if err := handler.ProcessPolicyRuleEvent(context.Background(), event.AgentUid, e.Rule); err != nil {
						logger.GetLogger().Error("Failed to process policy rule event", "error", err)
					}
				} else {
					logger.GetLogger().Warn("Policy status handler not configured, skipping policy rule event processing")
				}
			case *v1alpha.StreamEvent_HaStatus:
				// Log the HA status event
				logger.GetLogger().Debug("agw server: Received HA status event",
					"agentUid", event.AgentUid,
					"peer", e.HaStatus.Peer,
					"status", e.HaStatus.Status,
					"message", e.HaStatus.StatusMessage,
				)
				// Update HA criteria via handler
				if initializedPeer != nil && e.HaStatus.Peer != "" && haEventHandler != nil {
					switch e.HaStatus.Status {
					case v1alpha.HAStatus_HA_STATUS_KEEPALIVE_UP:
						haEventHandler.UpdateKeepalive(s.dpuListener.ctx, initializedPeer.uid, true)
						logger.GetLogger().Info("HA keepalive up from DPU",
							"agentUid", event.AgentUid,
							"peer", e.HaStatus.Peer)
					case v1alpha.HAStatus_HA_STATUS_KEEPALIVE_DOWN:
						haEventHandler.UpdateKeepalive(s.dpuListener.ctx, initializedPeer.uid, false)
						logger.GetLogger().Warn("HA keepalive down from DPU",
							"agentUid", event.AgentUid,
							"peer", e.HaStatus.Peer)
					case v1alpha.HAStatus_HA_STATUS_BULK_SYNC_DONE:
						haEventHandler.UpdateBulkSyncLocal(s.dpuListener.ctx, initializedPeer.uid, true)
						logger.GetLogger().Info("HA bulk sync local done from DPU",
							"agentUid", event.AgentUid,
							"peer", e.HaStatus.Peer)
					case v1alpha.HAStatus_HA_STATUS_BULK_SYNC_PEER_DONE:
						haEventHandler.UpdateBulkSyncPeer(s.dpuListener.ctx, initializedPeer.uid, true)
						logger.GetLogger().Info("HA bulk sync peer done from DPU",
							"agentUid", event.AgentUid,
							"peer", e.HaStatus.Peer)
					}
				}
			default:
				logger.GetLogger().Warn("Received unknown event type", "agentUid", event.AgentUid)
			}
		}
	}
}

func newServer(dpuListener *DPUListener) *AGWServer {
	return &AGWServer{
		dpuListener: dpuListener,
	}
}
