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
	"testing"

	"github.com/cilium/tetragon/pkg/k8s/crdutils"

	"github.com/stretchr/testify/require"
)

func TestRemoveSandboxPolicyCRDS(t *testing.T) {
	all_len := len(AllCRDs)
	crds := make([]crdutils.CRD, all_len)
	copy(crds, AllCRDs)
	crds = removeSandboxPolicyCRDs(crds)
	require.Equal(t, len(crds), all_len-2)
}
