package ha

import (
	"context"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"

	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/nxos"
	hav1 "github.com/isovalent/hubble-fgs/pkg/proto/ha/v1"
)

// Ha server object
type haServer struct {
	hav1.UnimplementedHaServer
	// this is swarm context
	Ctx context.Context
}

// Configuration and initialization of a swarm server object
func newServer(ctx context.Context) *haServer {
	s := &haServer{
		Ctx: ctx,
	}
	return s
}

// Starts running a gRPC server
func RunServer(ctx context.Context, port uint16) {
	conn, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Printf("Failed to listen: %v", err)
		return
	}

	grpcServer := grpc.NewServer()
	s := newServer(ctx)
	hav1.RegisterHaServer(grpcServer, s)
	err = grpcServer.Serve(conn)
	if err != nil {
		log.Printf("Failed to serve: %v", err)
	}
}

func (s *haServer) Adjacency(_ context.Context, req *hav1.AdjRequest) (*hav1.AdjResponse, error) {
	logger.GetLogger().Debug("Received MbrInfo", "mbr", req.MbrInfo)

	if !nxos.Nexus.IsPeerOk(s.Ctx, req.HaIp) {
		log.Printf("Unexpected peer: %s", req.HaIp)
		return &hav1.AdjResponse{
			Status:  hav1.ADJ_RESPONSE_STATUS_ADJ_FAILURE,
			Details: "Unexpected peer",
		}, nil
	}

	nxos.Nexus.HaSetMbrInfo(s.Ctx, req.HaIp, *req.MbrInfo)
	nxos.Nexus.HaReconcile(s.Ctx, req.HaIp, *req.MbrInfo)
	info := nxos.Nexus.HaGetMbrInfo(s.Ctx, req.HaIp)

	return &hav1.AdjResponse{
		Status:  hav1.ADJ_RESPONSE_STATUS_ADJ_SUCCESS,
		Details: "KeepAlive successful",
		MbrInfo: &info,
	}, nil
}
