// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package common

import (
	"fmt"

	"github.com/cilium/tetragon/cmd/tetra/common"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/spf13/cobra"
)

// ListPolicies is a helper to list a subset of the tracing policies
func ListPolicies(
	cmd *cobra.Command,
	output string,
	domain string,
	mapName func(name string) (string, bool), // mapName filters and renames policies
) error {
	res, err := ListTetragonPolicies(domain)
	if err != nil {
		return err
	}

	// keep only the policies we want in the list, and update their name
	if mapName != nil {
		for i := 0; i < len(res.Policies); i++ {
			pol := res.Policies[i]
			name, ok := mapName(pol.Name)
			if !ok {
				res.Policies = append(res.Policies[:i], res.Policies[i+1:]...)
				i--
			}
			pol.Name = name
		}
	}

	switch output {
	case "json":
		b, err := res.MarshalJSON()
		if err != nil {
			return fmt.Errorf("failed to generate json: %w", err)
		}
		cmd.Println(string(b))
	case "text":
		common.PrintTracingPolicies(
			cmd.OutOrStdout(),
			res.Policies,
			func(_ *tetragon.TracingPolicyStatus) bool { return false },
		)
	}
	return nil
}

func ListTetragonPolicies(domain string) (*tetragon.ListTracingPoliciesResponse, error) {
	c, err := common.NewClientWithDefaultContextAndAddress()
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}
	defer c.Close()

	res, err := c.Client.ListTracingPolicies(c.Ctx, &tetragon.ListTracingPoliciesRequest{Domain: domain})
	if err != nil || res == nil {
		return nil, fmt.Errorf("failed to list tracing policies: %w", err)
	}
	return res, nil
}
