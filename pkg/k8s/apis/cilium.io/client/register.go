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

	osscrdutils "github.com/cilium/tetragon-oss/pkg/k8s/crdutils"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/k8s/crdutils"
)

// NB(kkourt): We cannot do TracingPolicyCRD = ossclient.TracingPolicyCRD because the policies are
// different from OSS. We need to redfine them.
var (
	//go:embed crds/v1alpha1/cilium.io_tracingpolicies.yaml
	crdsv1Alpha1TracingPolicies []byte

	TracingPolicyCRD = osscrdutils.NewCRDBytes(
		v1alpha1.TPCRDName,
		v1alpha1.TPName,
		crdsv1Alpha1TracingPolicies)

	//go:embed crds/v1alpha1/cilium.io_tracingpoliciesnamespaced.yaml
	crdsv1Alpha1TracingPoliciesNamespaced []byte

	TracingPolicyNamespacedCRD = osscrdutils.NewCRDBytes(
		v1alpha1.TPNamespacedCRDName,
		v1alpha1.TPNamespacedName,
		crdsv1Alpha1TracingPoliciesNamespaced)

	//go:embed crds/v1alpha1/cilium.io_podinfo.yaml
	crdsv1Alpha1PodInfo []byte

	PodInfoCRD = osscrdutils.NewCRDBytes(
		v1alpha1.PICRDName,
		v1alpha1.PIName,
		crdsv1Alpha1PodInfo)

	//go:embed crds/v1alpha1/cilium.io_sandboxpolicies.yaml
	crdsv1Alpha1SandboxPolicy []byte

	SandboxPolicyCRD = osscrdutils.NewCRDBytes(
		"SandboxPolicy/v1alpha1",
		"sandboxpolicies.cilium.io",
		crdsv1Alpha1SandboxPolicy,
	)

	AllCRDs = []crdutils.CRD{
		TracingPolicyCRD,
		TracingPolicyNamespacedCRD,
		PodInfoCRD,
		SandboxPolicyCRD,
	}
)

func RemoveSandboxPolicyCRD() {
	// NB: This is ugly, but we do it to avoid changes in OSS
	for i := range AllCRDs {
		if AllCRDs[i].CRDName == SandboxPolicyCRD.CRDName {
			AllCRDs = append(AllCRDs[:i], AllCRDs[i+1:]...)
			break
		}
	}
}
