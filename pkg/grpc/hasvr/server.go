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

	"google.golang.org/grpc"

	"github.com/cilium/cilium/pkg/logging/logfields"
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
func RunServer(ctx context.Context, port uint16) error {
	conn, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		logger.GetLogger().Error("Fail to listen", logfields.Error, err)
		return err
	}

	grpcServer := grpc.NewServer()
	s := newServer(ctx)
	hav1.RegisterHaServer(grpcServer, s)
	err = grpcServer.Serve(conn)
	if err != nil {
		logger.GetLogger().Error("Fail to serve", logfields.Error, err)
		return err
	}
	return nil
}

func (s *haServer) Adjacency(_ context.Context, req *hav1.AdjRequest) (*hav1.AdjResponse, error) {
	logger.GetLogger().Debug("Received MbrInfo", "mbr", req.MbrInfo)

	if !nxos.Nexus.IsPeerOk(s.Ctx, req.HaIp) {
		logger.GetLogger().Debug("Unexpected peer", "peer", req.HaIp)
		return &hav1.AdjResponse{
			Status:  hav1.ADJ_RESPONSE_STATUS_ADJ_FAILURE,
			Details: "Unexpected peer",
		}, nil
	}

	nxos.Nexus.HaSetMbrInfo(s.Ctx, req.HaIp, *req.MbrInfo)
	nxos.Nexus.HaReconcile(s.Ctx, req.HaIp, *req.MbrInfo)
	info := nxos.Nexus.HaGetMbrInfo(s.Ctx, req.HaIp, true)

	return &hav1.AdjResponse{
		Status:  hav1.ADJ_RESPONSE_STATUS_ADJ_SUCCESS,
		Details: "KeepAlive successful",
		MbrInfo: &info,
	}, nil
}
