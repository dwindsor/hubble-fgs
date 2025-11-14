package dpu

import (
	"context"
	"fmt"

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

func newServer(dpuListener *DPUListener) *AGWServer {
	return &AGWServer{
		dpuListener: dpuListener,
	}
}
