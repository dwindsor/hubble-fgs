// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package vrf

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/openconfig/ygot/ygot"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
	model "github.com/isovalent/hubble-fgs/pkg/nxosmodel"
)

// ProgramAccessLists creates the IPv4 and IPv6 ACLs referenced by all redirect
// policy maps. These ACLs must be programmed once before any redirect
// configuration is written.
func ProgramAccessLists(ctx context.Context, handler gnmi.GnmiHandler) error {
	if err := programIPv4ACL(ctx, handler); err != nil {
		return err
	}
	return programIPv6ACL(ctx, handler)
}

// DeleteAccessLists removes the IPv4 and IPv6 redirect ACLs via gNMI DELETE.
// Counterpart to ProgramAccessLists, called during out-of-service and shutdown
// cleanup so only agent-managed MOs are removed.
func DeleteAccessLists(ctx context.Context, handler gnmi.GnmiHandler) error {
	ipv4Path := fmt.Sprintf(paths.AclIPv4Redirect, paths.AclNameIPv4, seqNum)
	if err := handler.Delete(ctx, ipv4Path); err != nil {
		logger.GetLogger().Warn("Failed to delete IPv4 redirect ACL", logfields.Error, err)
	}
	ipv6Path := fmt.Sprintf(paths.AclIPv6Redirect, paths.AclNameIPv6, seqNum)
	if err := handler.Delete(ctx, ipv6Path); err != nil {
		logger.GetLogger().Warn("Failed to delete IPv6 redirect ACL", logfields.Error, err)
	}
	return nil
}

func programIPv4ACL(ctx context.Context, handler gnmi.GnmiHandler) error {
	ipv4Any := "0.0.0.0"
	proto := uint8(0)
	sn := uint32(seqNum)
	ace := model.Cisco_NX_OSDevice_System_AclItems_Ipv4Items_NameItems_ACLList_SeqItems_ACEList{
		Action:    model.Cisco_NX_OSDevice_Acl_ActionType_permit,
		DstPrefix: &ipv4Any,
		Protocol:  &proto,
		SeqNum:    &sn,
		SrcPrefix: &ipv4Any,
	}

	jstr, err := ygot.EmitJSON(&ace, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Failed to emit JSON for IPv4 ACL", logfields.Error, err)
		return err
	}

	path := fmt.Sprintf(paths.AclIPv4Redirect, paths.AclNameIPv4, seqNum)
	if err := handler.Set(ctx, path, jstr); err != nil {
		logger.GetLogger().Error("Failed to program IPv4 ACL via gNMI", logfields.Error, err)
		return err
	}

	logger.GetLogger().Debug("IPv4 ACL programmed", "name", paths.AclNameIPv4)
	return nil
}

func programIPv6ACL(ctx context.Context, handler gnmi.GnmiHandler) error {
	ipv6Any := "0::0"
	proto := uint8(0)
	sn := uint32(seqNum)
	ace := model.Cisco_NX_OSDevice_System_AclItems_Ipv6Items_NameItems_ACLList_SeqItems_ACEList{
		Action:    model.Cisco_NX_OSDevice_Acl_ActionType_permit,
		DstPrefix: &ipv6Any,
		Protocol:  &proto,
		SeqNum:    &sn,
		SrcPrefix: &ipv6Any,
	}

	jstr, err := ygot.EmitJSON(&ace, &ygot.EmitJSONConfig{
		Format:        ygot.RFC7951,
		Indent:        "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{},
	})
	if err != nil {
		logger.GetLogger().Error("Failed to emit JSON for IPv6 ACL", logfields.Error, err)
		return err
	}

	path := fmt.Sprintf(paths.AclIPv6Redirect, paths.AclNameIPv6, seqNum)
	if err := handler.Set(ctx, path, jstr); err != nil {
		logger.GetLogger().Error("Failed to program IPv6 ACL via gNMI", logfields.Error, err)
		return err
	}

	logger.GetLogger().Debug("IPv6 ACL programmed", "name", paths.AclNameIPv6)
	return nil
}
