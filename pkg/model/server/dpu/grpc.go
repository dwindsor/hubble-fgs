package dpu

import (
	"context"
	"fmt"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
	"google.golang.org/grpc"
)

type FWAServer struct {
	v1alpha.UnimplementedL3L4NetworkPolicyServiceServer

	dpuListener *DPUListener
}

func (s *FWAServer) ReportStatus(_ context.Context, req *v1alpha.ReportStatusRequest) (*v1alpha.ReportStatusResponse, error) {
	status := reportRequestToDPU(req)
	s.dpuListener.ReportStatus(status)
	return &v1alpha.ReportStatusResponse{}, nil
}

func (s *FWAServer) Streaml3L4NetworkPolicy(req *v1alpha.Streaml3L4NetworkPolicyRequest, stream grpc.ServerStreamingServer[v1alpha.Streaml3L4NetworkPolicyResponse]) error {
	peer := s.dpuListener.addPeer(req.AgentUid)

	// The peer on reconnect needs to diff its current set with this set
	// and create the valid policy otherwise subsequent policy hash checks will
	// fail. If the peer builds on top of its current state without this check
	// then we could potentially leave policy rules orphaned in the peers
	// datapath.
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

	for {
		select {
		case <-s.dpuListener.ctx.Done():
			logger.GetLogger().Info("Client connection lost", "clientID", peer.uid)
			return nil
		case rule := <-peer.polCh:
			resp := dpuRuleToResponse(rule)
			err := stream.Send(resp)
			if err != nil {
				fmt.Printf("send error %s\n", err)
				return nil
			}
			logger.GetLogger().Debug("Pushed policy to client", "clientID", peer.uid, "policy", rule)
		}
	}
}

func (s *FWAServer) StreamDatapathConfig(req *v1alpha.StreamDatapathConfigRequest, stream grpc.ServerStreamingServer[v1alpha.StreamDatapathConfigResponse]) error {
	peer := s.dpuListener.addPeer(req.AgentUid)

	// The peer on reconnect needs to diff its current set with this set
	// and create the valid config otherwise subsequent config hash checks will
	// fail. If the peer builds on top of its current state without this check
	// then we could potentially leave config orphaned in the peers
	// datapath.
	for _, r := range peer.cfgSet {
		resp := v1alpha.StreamDatapathConfigResponse{
			Oper:   v1alpha.ConfigOperation_CONFIG_OPERATION_UPSERT,
			Config: r,
		}
		err := stream.Send(&resp)
		if err != nil {
			logger.GetLogger().Warn("Client send failed", "clientID", peer.uid, logfields.Error, err)
			return nil
		}
	}

	for {
		select {
		case <-s.dpuListener.ctx.Done():
			logger.GetLogger().Info("Client connection lost", "clientID", peer.uid)
			return nil
		case resp := <-peer.cfgCh:
			// Updating cfgSet to save desired config state
			// This is the only thread that writes to the CfgSet for this peer
			switch resp.Oper {
			case v1alpha.ConfigOperation_CONFIG_OPERATION_UNSPECIFIED:
				logger.GetLogger().Warn("Unspecified operation, passing message through to datapath")
			case v1alpha.ConfigOperation_CONFIG_OPERATION_UPSERT:
				peer.cfgSet[v1alpha.ConfigType(resp.Config.Type)] = resp.Config
			case v1alpha.ConfigOperation_CONFIG_OPERATION_DELETE:
				delete(peer.cfgSet, v1alpha.ConfigType(resp.Config.Type))
			default:
				logger.GetLogger().Error("Invalid operation, failed to send to datapath")
				continue
			}

			err := stream.Send(resp)
			if err != nil {
				logger.GetLogger().Warn("Client send failed", "clientID", peer.uid, logfields.Error, err)
				return nil
			}
			logger.GetLogger().Debug("Pushed config to client", "clientID", peer.uid, "config", resp)
		}
	}
}

func newServer(dpuListener *DPUListener) *FWAServer {
	return &FWAServer{
		dpuListener: dpuListener,
	}
}
