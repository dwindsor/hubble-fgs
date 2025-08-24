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
}

func (s *FWAServer) ReportStatus(_ context.Context, req *v1alpha.ReportStatusRequest) (*v1alpha.ReportStatusResponse, error) {
	server := GetDPUListener()
	status := reportRequestToDPU(req)
	server.ReportStatus(status)
	return &v1alpha.ReportStatusResponse{}, nil
}

func (s *FWAServer) Streaml3L4NetworkPolicy(req *v1alpha.Streaml3L4NetworkPolicyRequest, stream grpc.ServerStreamingServer[v1alpha.Streaml3L4NetworkPolicyResponse]) error {
	server := GetDPUListener()
	peer := server.addPeer(req.AgentUid)

	// The peer on reconnect needs to diff its current set with this set
	// and create the valid policy otherwise subsequent policy hash checks will
	// fail. If the peer builds on top of its current state without this check
	// then we could potentially leave policy rules orphaned in the peers
	// datapath.
	for _, r := range server.ruleSet {
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
		case <-server.ctx.Done():
			logger.GetLogger().Info("Client connection lost", "clientID", peer.uid)
			delete(server.peerGroup, peer.uid)
			return nil
		case rule := <-peer.ch:
			resp := dpuRuleToResponse(rule)
			err := stream.Send(resp)
			if err != nil {
				delete(server.peerGroup, peer.uid)
				fmt.Printf("send error %s\n", err)
				return nil
			}
			logger.GetLogger().Debug("Pushed policy to client", "clientID", peer.uid, "policy", rule)
		}
	}
}

func newServer() *FWAServer {
	return &FWAServer{}
}
