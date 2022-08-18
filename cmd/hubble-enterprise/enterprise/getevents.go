// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package enterprise

import (
	"encoding/json"
	"io"

	"github.com/cilium/tetragon/cmd/tetra/getevents"
	ossEncoder "github.com/cilium/tetragon/pkg/encoder"
	"github.com/isovalent/hubble-fgs/pkg/encoder"
)

func init() {
	getevents.GetEncoder = func(w io.Writer, colorMode ossEncoder.ColorMode, timestamps, compact bool) ossEncoder.EventEncoder {
		if compact {
			return encoder.NewEnterpriseEncoder(w, colorMode, timestamps)
		}
		return json.NewEncoder(w)
	}
}
