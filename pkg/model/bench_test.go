// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package model

import (
	"fmt"
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

func BenchmarkNamespaceMapToApplicationModel(b *testing.B) {
	// Create a large-ish process model to simulate real-world data
	numNamespaces := 5
	numWorkloadsPerNS := 10
	numContainersPerWL := 2
	numProcessesPerCont := 100
	numConnectionsPerProc := 50

	var processModels []*types.ProcessModel
	for ns := range numNamespaces {
		nsName := fmt.Sprintf("namespace-%d", ns)
		for wl := range numWorkloadsPerNS {
			wlName := fmt.Sprintf("workload-%d", wl)
			for cont := range numContainersPerWL {
				contID := fmt.Sprintf("container-%d", cont)
				for proc := range numProcessesPerCont {
					procName := fmt.Sprintf("process-%d", proc)

					var destinations []*types.Destination
					for conn := range numConnectionsPerProc {
						destinations = append(destinations, &types.Destination{
							DestinationNames: []string{"10.0.0." + string(rune('0'+conn))},
							Port:             8080,
							Protocol:         6, // TCP
							Stats: &types.DestinationStats{
								TxBytes: uint64(100 * (conn + 1)),
								RxBytes: uint64(200 * (conn + 1)),
							},
						})
					}

					processModels = append(processModels, &types.ProcessModel{
						Namespace: nsName,
						Workload: &types.Workload{
							Name: wlName,
							Kind: "Deployment",
						},
						Container: &types.ContainerInfo{
							Id:    contID,
							Name:  "cont-name",
							Image: "image-name",
						},
						Binary:     procName,
						BinaryArgs: "--arg1 --arg2",
						Dest:       destinations,
					})
				}
			}
		}
	}

	nsFilter := make(map[string]bool)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ProcessModelToApplicationModel(processModels, nsFilter, nil)
	}
}
