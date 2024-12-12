// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package errmetrics

import (
	"path/filepath"

	"github.com/cilium/tetragon/pkg/errmetrics"
)

var (
	ossPath = "modules/tetragon-oss/bpf"
)

func init() {
	ossGetFileIDs := errmetrics.GetFileIDs
	errmetrics.GetFileIDs = func() (map[int]string, error) {
		ret, err := ossGetFileIDs()
		if err != nil {
			return nil, err
		}

		for k, v := range ret {
			if v != errmetrics.UnknownFname {
				ret[k] = filepath.Join(ossPath, v)
			}
			// NB: once we have ee ids, we can fill in filenames here
		}

		return ret, nil
	}
}
