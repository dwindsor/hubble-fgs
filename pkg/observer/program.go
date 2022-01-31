//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package observer

import (
	"os"
	"path/filepath"

	"github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
)

func RemovePrograms(bpfDir, mapDir string) {
	for _, l := range sensors.GetAllPrograms() {
		sensors.RemoveProgram(bpfDir, l)
	}

	for _, m := range sensors.GetAllMaps() {
		if m.Map != nil {
			m.Map.Close()
			m.Map = nil
		}
		os.Remove(filepath.Join(mapDir, m.Name))
	}
	os.Remove(bpfDir)
	os.Remove(mapDir)
	btf.FreeCachedBTF()
}
