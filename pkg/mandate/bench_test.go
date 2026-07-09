// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package mandate

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/cilium/cilium/pkg/time"
	"github.com/stretchr/testify/require"

	mandateconf "github.com/isovalent/hubble-fgs/pkg/mandate/conf"
)

func BenchmarkMandate(b *testing.B) {
	const numPolicies = 1000
	tmpDir := b.TempDir()
	tsm := NewTestSensorManager()
	cnf := mandateconf.ManagerConf{
		URL:           filepath.Join(tmpDir, "mandate.yaml"),
		RefreshPeriod: 1 * time.Second,
	}
	mgr, err := NewManager(cnf, tsm, nil)
	require.NoError(b, err)

	var policies []Policy
	policyFmt := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "policy-%d"
spec:
  kprobes: []
`

	for i := range numPolicies {
		name := filepath.Join(tmpDir, "policy-"+strconv.Itoa(i)+".yaml")
		var bytes []byte
		err = os.WriteFile(name, fmt.Appendf(bytes, policyFmt, i), 0644)
		require.NoError(b, err)
		pol := Policy{
			URL: name,
		}
		require.NoError(b, pol.init(&Mandate{}))
		policies = append(policies, pol)
	}

	obj := &Obj{
		Mandate: Mandate{
			Policies: policies,
		},
	}

	b.ResetTimer()
	for range b.N {
		clear(tsm.pols)
		refrAtt := mgr.attLog.NewAttempt("benchmark")
		res, err := mgr.fetchAndLoadPolicies(b.Context(), refrAtt, obj)
		require.NoError(b, err)
		err = refrAtt.Complete(err)
		require.NoError(b, err)
		require.Len(b, res.loadedPolicies, numPolicies)
	}
}
