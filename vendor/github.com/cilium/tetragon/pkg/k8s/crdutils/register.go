// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.
package crdutils

import (
	osscrdutils "github.com/cilium/tetragon-oss/pkg/k8s/crdutils"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
)

type CRDOptions = osscrdutils.CRDOptions

type CRD = osscrdutils.CRD

func NewCRDBytes(crdName, resName string, crdBytes []byte) CRD {
	return osscrdutils.NewCRDBytes(crdName, resName, crdBytes)
}

func RegisterCRDs(clientset apiextensionsclient.Interface, crds []CRD) error {
	return osscrdutils.RegisterCRDs(clientset, crds)
}

func RegisterCRDsWithOptions(clientset apiextensionsclient.Interface, crds []CRD, opts CRDOptions) error {
	return osscrdutils.RegisterCRDsWithOptions(clientset, crds, opts)
}
