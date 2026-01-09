// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package attempt

import "encoding/json"

// NB: this is awkward but having JSON marshalling for errors (see MarshalJSON), which does not
// happen for the standard error type.
type Result struct {
	err error
}

func (e Result) MarshalJSON() ([]byte, error) {
	if e.err == nil {
		return json.Marshal(struct {
			Success bool
		}{
			Success: true,
		})
	}
	return json.Marshal(struct {
		Success bool
		Error   string
	}{
		Success: false,
		Error:   e.err.Error(),
	})
}
