// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build sudo_tests

package server_test

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/bpftest"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

func populateProcessTree(b *testing.B, m *ebpf.Map, n int) {
	b.Helper()
	for i := range n {
		key := types.ProcessTreeKey{
			WLID:  0,
			Depth: 1,
			Self:  uint64(i + 1),
		}
		val := types.ProcessTreeValue{
			ExecCount:  1,
			InInitTree: true,
		}
		bin := fmt.Sprintf("/usr/bin/proc-%d", i)
		copy(val.Binary[:], bin)
		args := "--arg1\x00--arg2\x00"
		copy(val.Args[:], args)
		require.NoError(b, m.Update(key, val, ebpf.UpdateAny))
	}
}

// populateDestinations inserts destsPerProc synthetic destination entries per
// process into the destination_endpoint_map. Each destination is a unique IPv4
// address with DestinationSourceBPF so it hits the IP-based lookup path.
func populateDestinations(b *testing.B, m *ebpf.Map, nProcs, destsPerProc int) {
	b.Helper()
	for i := range nProcs {
		for j := range destsPerProc {
			key := types.DestinationEndpointKey{
				LocalId:           uint64(i + 1),
				LocalWLID:         0,
				DestinationId:     uint64(i*destsPerProc + j + 1),
				DestinationSource: types.DestinationSourceBPF,
				DestinationPort:   uint32(8000 + j),
				Protocol:          6,
			}
			// Encode a unique IPv4 address in little-endian into AddrCreate[0].
			ip := uint32(0x0A000001 + uint32(i*destsPerProc+j)) // 10.0.x.y
			var addr [2]uint64
			var buf [4]byte
			binary.LittleEndian.PutUint32(buf[:], ip)
			addr[0] = uint64(binary.LittleEndian.Uint32(buf[:]))
			val := types.DestinationEndpointValue{
				TxBytes:    100,
				RxBytes:    200,
				AddrCreate: addr,
				Port:       uint32(8000 + j),
				Protocol:   6,
			}
			require.NoError(b, m.Update(key, val, ebpf.UpdateAny))
		}
	}
}

// BenchmarkGetProcessModel measures the full getProcessModel path against real
// pinned BPF maps. Unlike BenchmarkNamespaceMapToApplicationModel (which
// benchmarks the in-memory conversion after data is already assembled), this
// exercises BPF map iteration, decodeBinaryArgs, the binaryArgsCache, and
// per-process slice assembly from scratch each iteration.
func BenchmarkGetProcessModel(b *testing.B) {
	for _, n := range []int{1000, 10000, 46000} {
		b.Run(fmt.Sprintf("procs=%d/dests=0", n), func(b *testing.B) {
			ctx := b.Context()

			srv := bpftest.StartMinimalTetragonModel(ctx, b)

			mapPath := filepath.Join(bpf.MapPrefixPath(), "process_tree_map")
			m, err := ebpf.LoadPinnedMap(mapPath, nil)
			require.NoError(b, err)
			defer m.Close()
			populateProcessTree(b, m, n)

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				res, err := srv.GetProcessModel(ctx, []string{}, false)
				require.NoError(b, err)
				_ = res
			}
		})
	}

	for _, totalDests := range []int{20000, 40000, 65000} {
		procs := 10000
		destsPerProc := max(totalDests/procs, 1)
		b.Run(fmt.Sprintf("procs=%d/dests=%d", procs, totalDests), func(b *testing.B) {
			ctx := b.Context()

			srv := bpftest.StartMinimalTetragonModel(ctx, b)

			treeMapPath := filepath.Join(bpf.MapPrefixPath(), "process_tree_map")
			tm, err := ebpf.LoadPinnedMap(treeMapPath, nil)
			require.NoError(b, err)
			defer tm.Close()
			populateProcessTree(b, tm, procs)

			destMapPath := filepath.Join(bpf.MapPrefixPath(), "destination_endpoint_map")
			dm, err := ebpf.LoadPinnedMap(destMapPath, nil)
			require.NoError(b, err)
			defer dm.Close()
			populateDestinations(b, dm, procs, destsPerProc)

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				res, err := srv.GetProcessModel(ctx, []string{}, false)
				require.NoError(b, err)
				_ = res
			}
		})
	}
}
