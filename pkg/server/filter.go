// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package server

import (
	"context"
	"log/slog"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/sensors"
	ossserver "github.com/cilium/tetragon/pkg/server"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	"github.com/isovalent/hubble-fgs/pkg/policies"
)

// filterServer decorates the gRPC server so an AddTracingPolicy whose
// spec.nodeSelector does not match hostLabels is recorded as skipped (loaded
// as TP_STATE_SKIPPED) instead of loaded. Every other RPC is promoted
// unchanged from the embedded server.
type filterServer struct {
	tetragon.FineGuidanceSensorsServer
	sm         *sensors.Manager
	hostLabels map[string]string
	log        *slog.Logger
}

// NewFilterServer wraps inner so an AddTracingPolicy is recorded as skipped
// when the policy's spec.nodeSelector does not match hostLabels. If hostLabels
// is empty (no host labels were resolved), inner is returned unwrapped,
// leaving the gRPC path ungated.
func NewFilterServer(inner tetragon.FineGuidanceSensorsServer, sm *sensors.Manager, log *slog.Logger, hostLabels map[string]string) tetragon.FineGuidanceSensorsServer {
	if len(hostLabels) == 0 {
		return inner
	}
	return &filterServer{FineGuidanceSensorsServer: inner, sm: sm, hostLabels: hostLabels, log: log}
}

func (s *filterServer) AddTracingPolicy(ctx context.Context, req *tetragon.AddTracingPolicyRequest) (*tetragon.AddTracingPolicyResponse, error) {
	tp, err := tracingpolicy.FromYAML(req.GetYaml())
	if err == nil && policies.SkipTracingPolicyForNode(tp, s.hostLabels, s.log) {
		s.log.Info("Skipping TracingPolicy (gRPC): node does not match spec.nodeSelector",
			"metadata.namespace", tp.TpNamespace(),
			"metadata.name", tp.TpName())
		// Record it in the grpc domain a loaded gRPC policy would use, so list
		// and delete treat skipped and loaded policies identically.
		gtp := &ossserver.GRPCTracingPolicy{TracingPolicy: tp}
		if req.GetDomain() != "" {
			gtp.Domain = req.GetDomain()
		}
		if err := s.sm.AddTracingPolicyWithState(ctx, gtp, sensors.SkippedState); err != nil {
			return nil, err
		}
		return &tetragon.AddTracingPolicyResponse{}, nil
	}
	// Parse errors and the accepted path both go to the wrapped server, which
	// returns its own canonical error for malformed input.
	return s.FineGuidanceSensorsServer.AddTracingPolicy(ctx, req)
}
