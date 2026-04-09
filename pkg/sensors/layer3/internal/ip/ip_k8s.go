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

package ip

import (
	"github.com/cilium/tetragon/pkg/sensors/program"

	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/workloadid"
)

var (
	// This is needed for pkg/workloadid for the application model to do the
	// cgroup ID / workload resolution, ideally the MapBuilder should be in
	// the layer3_linux.go file but we have an import cycle.
	CgroupIDToWorkloadIDMap = program.MapBuilder(workloadid.CgroupIDWorkloadIDMapName, FdLookupKprobeProcessTree, FdLookupFentryProcessTree)
)

func appendApplicationModelMaps(maps []*program.Map) []*program.Map {
	if enterpriseOption.Config.EnableApplicationModel {
		maps = append(maps, CgroupIDToWorkloadIDMap)
		CgroupIDToWorkloadIDMap.SetMaxEntries(workloadid.MaxWorkloadID)
	}
	return maps
}
