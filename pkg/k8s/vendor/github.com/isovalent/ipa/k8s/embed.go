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

import _ "embed"

// This embedding module (see https://pkg.go.dev/embed) allows other repos to
// pull in the common CRDs defined here using Go-native vendoring mechnanisms

//go:embed crds/cilium.io/v1alpha1/cilium.io_tetragonnetworkpolicies.yaml
var CRDsv1Alpha1TetragonNetworkPolicies []byte

//go:embed crds/cilium.io/v1alpha1/cilium.io_tetragonnetworkpoliciesnamespaced.yaml
var CRDsv1Alpha1TetragonNetworkPoliciesNamespaced []byte

//go:embed crds/isovalent.com/v1alpha1/isovalent.com_smartswitches.yaml
var CRDsv1Alpha1SmartSwitches []byte

//go:embed crds/isovalent.com/v1alpha1/isovalent.com_smartswitchnetworkpolicies.yaml
var CRDsv1Alpha1SmartSwitchNetworkPolicy []byte

//go:embed crds/isovalent.com/v1alpha1/isovalent.com_tetragonnodes.yaml
var CRDsv1Alpha1TetragonNodes []byte
