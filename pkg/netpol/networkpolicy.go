// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !nok8s

package netpol

import (
	"fmt"

	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/netpol/library"
	"github.com/isovalent/hubble-fgs/pkg/netpolstate"
)

// applyPolicies and unapplyPolicies program the datapath via netpolstate. They
// are package variables so Reconcile-level unit tests can stub out the
// BPF-backed state without loading sensors.
var (
	applyPolicies = func(policies []*types.TetragonNetworkPolicy) error {
		return netpolstate.Get().AddPolicies(policies)
	}
	unapplyPolicies = func(policies []*types.TetragonNetworkPolicy) error {
		return netpolstate.Get().RemovePolicies(policies)
	}
)

// getCurrentSlot returns the slot currently holding resourceName's policy, the
// story there (nil if neither slot is populated), and the free slot to stage the
// next version into. The repository double-buffers between the canonical name
// and a "__"-prefixed alternate so an update loads the new version before
// unloading the old one (gap-free update).
func getCurrentSlot(resourceName string) (string, *library.PolicyStory, string) {
	altName := "__" + resourceName
	if story := library.GetRepository().Get(resourceName); story != nil {
		return resourceName, story, altName
	}
	if story := library.GetRepository().Get(altName); story != nil {
		return altName, story, resourceName
	}
	return resourceName, nil, altName
}

func deleteNetworkPolicy(name string) error {
	story := library.GetRepository().Get(name)
	if story == nil {
		return fmt.Errorf("policy %q does not exist", name)
	}
	if err := unapplyPolicies(story.IrPolicy); err != nil {
		return fmt.Errorf("removing policy %q failed: %w", name, err)
	}
	library.GetRepository().Delete(name)
	return nil
}

func loadPolicy(policyStory *library.PolicyStory) error {
	if library.GetRepository().Get(policyStory.Title) != nil {
		return fmt.Errorf("loading policy story %s would overwrite existing network policy", policyStory.Title)
	}

	existTest := fmt.Sprintf("__%s", policyStory.Title)
	if library.GetRepository().Get(existTest) != nil {
		return fmt.Errorf("loading policy story %s would overwrite existing network policy", policyStory.Title)
	}

	library.GetRepository().Add(policyStory)

	if err := applyPolicies(policyStory.IrPolicy); err != nil {
		// Roll back so the failed policy isn't left looking loaded, which would
		// block retries with "would overwrite".
		library.GetRepository().Delete(policyStory.Title)
		return fmt.Errorf("failed create match label from policy set %s: %w", policyStory.Title, err)
	}
	return nil
}
