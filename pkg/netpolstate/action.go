// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !nok8s

package netpolstate

import (
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

func calculateAction(a *types.TetragonNetworkAction) *record.DatapathAction {
	deny := record.PolicyNone
	if a.EnforceAction != nil {
		if a.EnforceAction.Deny {
			deny |= record.PolicyDeny
		}
		if a.EnforceAction.Allow {
			deny |= record.PolicyAllow
		}
		if a.EnforceAction.Reject {
			deny |= record.PolicyReject | record.PolicyDeny
		}
	}

	return &record.DatapathAction{Action: deny}
}
