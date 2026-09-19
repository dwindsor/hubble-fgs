// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package hec

import (
	"context"
	"fmt"
	"net/url"

	protovalidate "buf.build/go/protovalidate"
	"github.com/cilium/tetragon/pkg/logger"
	splunkV1 "github.com/isovalent/ipa/splunk/v1alpha"
)

type SplunkService struct {
	splunkV1.UnimplementedSplunkServiceServer
}

func NewSplunkService() *SplunkService {
	return &SplunkService{}
}

func (s *SplunkService) GetHecSettings(_ context.Context, _ *splunkV1.GetHecSettingsRequest) (*splunkV1.GetHecSettingsResponse, error) {
	current := GetConfig().Load()
	endpoint := ""
	if current != nil && current.SplunkHECEndpoint != nil {
		endpoint = current.SplunkHECEndpoint.String()
	}

	response := &splunkV1.GetHecSettingsResponse{}
	if current != nil {
		response.Endpoint = endpoint
		response.Token = current.SplunkHECToken
		response.SourceTypes = append([]string{}, current.SplunkHECSourcetypes...)
	}
	return response, nil
}

func (s *SplunkService) SetHecSettings(_ context.Context, req *splunkV1.SetHecSettingsRequest) (*splunkV1.SetHecSettingsResponse, error) {
	if err := protovalidate.GlobalValidator.Validate(req); err != nil {
		return nil, fmt.Errorf("invalid Splunk HEC settings: %w", err)
	}

	var endpoint *url.URL
	var err error
	if req.Endpoint != "" {
		endpoint, err = url.Parse(req.Endpoint)
		if err != nil {
			return nil, err
		}
		logger.GetLogger().Info("Exporting JSON records to the Splunk HTTP Event Collector", "endpoint", req.Endpoint, "sourceTypes", req.SourceTypes)
	} else {
		logger.GetLogger().Info("Disabling export to the Splunk HTTP Event Collector")
	}

	config := GetConfig()
	current := config.Load()
	updated := &Config{}
	if current != nil {
		*updated = *current
	}
	updated.SplunkHECEndpoint = endpoint
	updated.SplunkHECToken = req.Token
	updated.SplunkHECSourcetypes = append([]string{}, req.SourceTypes...)
	config.Store(updated)
	return &splunkV1.SetHecSettingsResponse{}, nil
}
