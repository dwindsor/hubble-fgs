// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package policies

import (
	"context"
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"sigs.k8s.io/yaml"

	"github.com/isovalent/hubble-fgs/pkg/sandboxpolicy"
)

type remoteLoader struct {
	alertRuleService     tetragon.AlertServiceClient
	networkPolicyService tetragon.NetworkPolicyServiceClient
	tracingPolicyService tetragon.FineGuidanceSensorsClient

	domain string
}

func (r *remoteLoader) OnTracingPolicy(ctx context.Context, _ string, bytes []byte) error {
	_, err := r.tracingPolicyService.AddTracingPolicy(ctx, &tetragon.AddTracingPolicyRequest{Yaml: string(bytes), Domain: r.domain})
	return err
}

func (r *remoteLoader) OnSandboxPolicy(ctx context.Context, fname string, bytes []byte) error {
	pol, err := sandboxpolicy.FromYAML(string(bytes))
	if err != nil {
		return err
	}

	var tp any
	switch sp := pol.(type) {
	case *v1alpha1.SandboxPolicy:
		tp, err = sandboxpolicy.ToTracingPolicy(sp)
		if err != nil {
			return err
		}
	case *v1alpha1.SandboxPolicyNamespaced:
		tp, err = sandboxpolicy.ToTracingPolicyNamespaced(sp)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unexpected parsing result of %s", fname)
	}
	out, err := yaml.Marshal(tp)
	if err != nil {
		return err
	}

	// Store current domain
	currDomain := r.domain
	defer func() {
		// Restore domain
		r.domain = currDomain
	}()
	// Enforce SandboxDomain for sandbox policies
	r.domain = sandboxpolicy.SandboxDomain
	return r.OnTracingPolicy(ctx, fname, out)
}

func (r *remoteLoader) OnNetworkPolicy(ctx context.Context, _ string, bytes []byte) error {
	_, err := r.networkPolicyService.AddNetworkPolicyFromYAML(ctx, &tetragon.AddNetworkPolicyFromYAMLRequest{Yaml: string(bytes)})
	return err
}

func (r *remoteLoader) OnAlertRule(ctx context.Context, _ string, bytes []byte) error {
	_, err := r.alertRuleService.AddAlertRuleFromYAML(ctx, &tetragon.AddAlertRuleFromYAMLRequest{Yaml: string(bytes), Domain: r.domain})
	return err
}

func NewRemoteLoader(alertRuleService tetragon.AlertServiceClient,
	networkPolicyService tetragon.NetworkPolicyServiceClient,
	tracingPolicyService tetragon.FineGuidanceSensorsClient, domain string) Loader {
	return &remoteLoader{
		alertRuleService:     alertRuleService,
		networkPolicyService: networkPolicyService,
		tracingPolicyService: tracingPolicyService,
		domain:               domain,
	}
}
