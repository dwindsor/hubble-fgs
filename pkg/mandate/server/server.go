//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package server

import (
	"context"
	"time"

	api "github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/isovalent/hubble-fgs/pkg/mandate"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Server struct {
	api.UnimplementedMandateServiceServer
	mgr mandate.Manager
}

func New(mgr mandate.Manager) *Server {
	return &Server{
		mgr: mgr,
	}
}

var (
	disabledErr = status.Errorf(codes.Unavailable, "mandate service is disabled")
)

func (s *Server) GetMandateStatus(_ context.Context, _ *api.GetMandateStatusReq) (*api.GetMandateStatusRes, error) {
	if s.mgr == nil {
		return nil, disabledErr
	}

	status := s.mgr.Status()
	ret := api.GetMandateStatusRes{
		Conf: &api.MandateConf{
			Url:           status.Conf.URL,
			RefreshPeriod: durationpb.New(status.Conf.RefreshPeriod),
		},
		Running: status.Running,
		Log:     status.Log.ToProto(),
	}
	if status.Mandate != nil {
		ret.LoadedMandate = &api.Mandate{
			Version:  status.Mandate.Version,
			LoadedAt: timestamppb.New(status.Mandate.LoadedAt),
			Checksum: status.Mandate.Checksum,
		}
	}

	return &ret, nil
}

func (s *Server) MandateConfigure(_ context.Context, cfg *api.MandateConfigureReq) (*api.MandateConfigureRes, error) {
	if s.mgr == nil {
		return nil, disabledErr
	}

	var duration *time.Duration
	if cfg.RefreshPeriod != nil {
		v := cfg.RefreshPeriod.AsDuration()
		duration = &v
	}

	err := s.mgr.Configure(mandate.ConfArg{
		URL:           cfg.Url,
		RefreshPeriod: duration,
		Refresh:       cfg.Refresh,
	})
	if err != nil {
		return nil, err
	}

	return &api.MandateConfigureRes{}, nil
}
