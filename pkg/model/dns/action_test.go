package dns

import (
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/stretchr/testify/assert"
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
	assert.NoError(t, err)
	assert.Equal(t, record.PolicyDeny, da.Deny)
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
	assert.NoError(t, err)
	assert.Equal(t, record.PolicyNone, da.Deny)
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
	assert.NoError(t, err)
	assert.Equal(t, record.PolicyAllow, da.Deny)
}
