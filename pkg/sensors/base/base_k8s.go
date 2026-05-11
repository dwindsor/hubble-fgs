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

package base

import (
	"github.com/cilium/tetragon/pkg/sensors/program"

	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base/procfs"
	"github.com/isovalent/hubble-fgs/pkg/workloadid"
)

var (
	// This is needed for pkg/workloadid for the application model to do the
	// cgroup ID / workload resolution.
	CgroupIDToWorkloadIDMapProgs = []*program.Program{Execve, ExecveV53, ExecveV511, ExecveV61, ExecveV612, Exit, ExitV511, procfs.ProcFSWalkKprobe, procfs.ProcFSWalkFentry}

	// Create now, might be recreated in a call to AddCgroupIdToWorkloadIDMapProgs
	CgroupIDToWorkloadIDMap = program.MapBuilder(workloadid.CgroupIDWorkloadIDMapName, CgroupIDToWorkloadIDMapProgs...)
)

func AddCgroupIdToWorkloadIDMapProgs(progs []*program.Program) {
	CgroupIDToWorkloadIDMapProgs = append(CgroupIDToWorkloadIDMapProgs, progs...)
	CgroupIDToWorkloadIDMap = program.MapBuilder(workloadid.CgroupIDWorkloadIDMapName, CgroupIDToWorkloadIDMapProgs...)
}

func appendApplicationModelMaps(maps []*program.Map) []*program.Map {
	if enterpriseOption.Config.EnableApplicationModel {
		maps = append(maps, CgroupIDToWorkloadIDMap)
		CgroupIDToWorkloadIDMap.SetMaxEntries(workloadid.MaxWorkloadID)
	}
	return maps
}
