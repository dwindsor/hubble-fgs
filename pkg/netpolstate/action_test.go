// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package netpolstate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

// These transformations seems a bit unnecessary, but lets just allow
// it for now.
func TestCalculateDeny(t *testing.T) {
	enforce := &types.TetragonEnforceAction{
		Deny:  true,
		Allow: false,
	}
	a := &types.TetragonNetworkAction{
		QuotaAction:   nil,
		EnforceAction: enforce,
	}
	da, err := calculateAction(a)
	require.NoError(t, err)
	assert.Equal(t, record.PolicyDeny, da.Action)
}

func TestCalculateNoDeny(t *testing.T) {
	enforce := &types.TetragonEnforceAction{
		Deny:  false,
		Allow: false,
	}
	a := &types.TetragonNetworkAction{
		QuotaAction:   nil,
		EnforceAction: enforce,
	}
	da, err := calculateAction(a)
	require.NoError(t, err)
	assert.Equal(t, record.PolicyNone, da.Action)
}

func TestCalculateAllow(t *testing.T) {
	enforce := &types.TetragonEnforceAction{
		Deny:  false,
		Allow: true,
	}
	a := &types.TetragonNetworkAction{
		QuotaAction:   nil,
		EnforceAction: enforce,
	}
	da, err := calculateAction(a)
	require.NoError(t, err)
	assert.Equal(t, record.PolicyAllow, da.Action)
}
