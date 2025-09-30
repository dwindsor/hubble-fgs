//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package netpol

import (
	"context"
	"fmt"

	"github.com/cilium/tetragon/pkg/logger"
	"gopkg.in/yaml.v3"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/model/dns"
	"github.com/isovalent/hubble-fgs/pkg/netpol/library"
)

type NetworkPolicyManager struct {
	ctx context.Context
	tetragon.UnimplementedNetworkPolicyServiceServer
}

func New(ctx context.Context) *NetworkPolicyManager {
	return &NetworkPolicyManager{
		ctx: ctx,
	}
}

func (m *NetworkPolicyManager) AddNetworkPolicyFromYAML(_ context.Context, req *tetragon.AddNetworkPolicyFromYAMLRequest) (*tetragon.AddNetworkPolicyResponse, error) {
	np, err := FromYAML(req.Yaml)
	if err != nil {
		return nil, err
	}
	if np == nil {
		return nil, fmt.Errorf("unknown policy kind")
	}

	policies, err := ToTetragonNetworkPolicies(np)
	if err != nil {
		return nil, fmt.Errorf("failed to convert TetragonNetworkPolicy %s to internal representation: %w", np.Name, err)
	}

	err = loadPolicy(&library.PolicyStory{
		Title:       np.Name,
		Rules:       make(map[string]uint64),
		CRDPolicy:   np,
		CRDNSPolicy: nil,
		IrPolicy:    policies,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load TetragonNetworkPolicy: %w", err)
	}

	logger.GetLogger().Info("GRPC Added TetragonNetworkPolicy with success", "Name", np.Name)

	return &tetragon.AddNetworkPolicyResponse{}, nil
}

func (m *NetworkPolicyManager) DeleteNetworkPolicy(_ context.Context, req *tetragon.DeleteNetworkPolicyRequest) (*tetragon.DeleteNetworkPolicyResponse, error) {
	story := library.GetRepository().Get(req.Name)
	if story == nil {
		return nil, fmt.Errorf("policy does not exist")
	}

	if err := dns.RemoveNetworkPolicySet(req.Name, story.IrPolicy); err != nil {
		return nil, fmt.Errorf("abort removing policy failed")
	}

	library.GetRepository().Delete(req.Name)
	logger.GetLogger().Info("network policy deleted", "title", req.Name)

	return &tetragon.DeleteNetworkPolicyResponse{}, nil
}

func (m *NetworkPolicyManager) ListNetworkPolicy(context.Context, *tetragon.ListNetworkPolicyRequest) (*tetragon.ListNetworkPolicyResponse, error) {
	npiList := []*tetragon.NetworkPolicyInfo{}
	list := library.GetRepository().GetList()
	for _, n := range list {
		npi := &tetragon.NetworkPolicyInfo{
			Name: n,
		}
		npiList = append(npiList, npi)
	}
	return &tetragon.ListNetworkPolicyResponse{
		Info: npiList,
	}, nil
}

func (m *NetworkPolicyManager) GetNetworkPolicy(_ context.Context, req *tetragon.GetNetworkPolicyRequest) (*tetragon.GetNetworkPolicyResponse, error) {
	policy := library.GetRepository().Get(req.Name)
	if policy == nil {
		return nil, fmt.Errorf("policy does not exist")
	}

	crd, err := yaml.Marshal(policy.CRDPolicy)
	if err != nil {
		return nil, fmt.Errorf("error marshalling data")
	}

	return &tetragon.GetNetworkPolicyResponse{
		Name: policy.Title,
		Yaml: string(crd),
	}, nil
}
