// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package client

import (
	_ "embed"
	"log/slog"

	osscrdutils "github.com/cilium/tetragon-oss/pkg/k8s/crdutils"
	"github.com/cilium/tetragon/pkg/k8s/crdutils"
	ipak8s "github.com/isovalent/ipa/k8s"
)

var (
	SmartSwitchCRD = osscrdutils.NewCRDBytes(
		slog.Default(),
		"SmartSwitch/v1alpha1",
		"smartswitches.isovalent.com",
		ipak8s.CRDsv1Alpha1SmartSwitches,
	)

	SmartSwitchNetworkPolicyCRD = osscrdutils.NewCRDBytes(
		slog.Default(),
		"SmartSwitchNetworkPolicy/v1alpha1",
		"smartswitchnetworkpolicies.isovalent.com",
		ipak8s.CRDsv1Alpha1SmartSwitchNetworkPolicy,
	)

	TetragonNodeCRD = osscrdutils.NewCRDBytes(
		slog.Default(),
		"TetragonNode/v1alpha1",
		"tetragonnodes.isovalent.com",
		ipak8s.CRDsv1Alpha1TetragonNodes,
	)

	AllCRDs = []crdutils.CRD{
		SmartSwitchCRD,
		SmartSwitchNetworkPolicyCRD,
		TetragonNodeCRD,
	}
)
