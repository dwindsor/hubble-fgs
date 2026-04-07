// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this
// information or reproduction of this material is strictly forbidden unless
// prior written permission is obtained from Isovalent Inc.

package k8s

import (
	"embed"
	"fmt"

	ciliumiov1alpha1 "github.com/isovalent/ipa/k8s/crds/cilium.io/v1alpha1"
	isovalentcomv1alpha1 "github.com/isovalent/ipa/k8s/crds/isovalent.com/v1alpha1"
)

// These variables exist for backwards compatibility.
// Callers should prefer using the EmbedFS directly.
var (
	// CRDsv1Alpha1TetragonNetworkPolicies contains the embedded CRD.
	//
	// Deprecated: Use github.com/isovalent/ipa/k8s/crds/cilium.io/v1alpha1.EmbedFS instead.
	CRDsv1Alpha1TetragonNetworkPolicies = mustReadFS(ciliumiov1alpha1.EmbedFS, "cilium.io_tetragonnetworkpolicies.yaml")
	// CRDsv1Alpha1TetragonNetworkPoliciesNamespaced contains the embedded CRD.
	//
	// Deprecated: Use github.com/isovalent/ipa/k8s/crds/cilium.io/v1alpha1.EmbedFS instead.
	CRDsv1Alpha1TetragonNetworkPoliciesNamespaced = mustReadFS(ciliumiov1alpha1.EmbedFS, "cilium.io_tetragonnetworkpoliciesnamespaced.yaml")
	// CRDsv1Alpha1SmartSwitches contains the embedded CRD.
	//
	// Deprecated: Use github.com/isovalent/ipa/k8s/crds/isovalent.com/v1alpha1.EmbedFS instead.
	CRDsv1Alpha1SmartSwitches = mustReadFS(isovalentcomv1alpha1.EmbedFS, "isovalent.com_smartswitches.yaml")
	// CRDsv1Alpha1SmartSwitchNetworkPolicy contains the embedded CRD.
	//
	// Deprecated: Use github.com/isovalent/ipa/k8s/crds/isovalent.com/v1alpha1.EmbedFS instead.
	CRDsv1Alpha1SmartSwitchNetworkPolicy = mustReadFS(isovalentcomv1alpha1.EmbedFS, "isovalent.com_smartswitchnetworkpolicies.yaml")
	// CRDsv1Alpha1TetragonNodes contains the embedded CRD.
	//
	// Deprecated: Use github.com/isovalent/ipa/k8s/crds/isovalent.com/v1alpha1.EmbedFS instead.
	CRDsv1Alpha1TetragonNodes = mustReadFS(isovalentcomv1alpha1.EmbedFS, "isovalent.com_tetragonnodes.yaml")
)

func mustReadFS(fs embed.FS, name string) []byte {
	b, err := fs.ReadFile(name)
	if err != nil {
		panic(fmt.Sprintf("failed to read embedded file %s: %v", name, err))
	}
	return b
}
