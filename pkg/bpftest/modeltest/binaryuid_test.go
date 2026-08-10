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

package modeltest

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/bpf"

	"github.com/isovalent/hubble-fgs/pkg/model/datapath"
)

// binaryUIDKey mirrors the unexported processTreeBinaryUIDKey in
// pkg/model/datapath. Redefined here rather than exported, since the helper is
// temporary.
type binaryUIDKey struct {
	binary [datapath.PATH_SIZE]byte
	// args, left zero: GetBinaryId registers selector binaries under the
	// zero-args key, which is the entry this helper deletes.
	_ [datapath.PATH_SIZE]byte
}

// releaseLeakedBinaryUIDs deletes the process_tree_binary_uid_map entries a
// policy's processSelector registered, after the test that loaded it finishes.
//
// RemovePolicy never releases them, so an entry outlives its policy. TestModel
// shares one agent, and __find_my_self prefers the zero-args entry while its
// ignore_args bit is set, so a later exec of the same binary inherits the dead
// policy's identity and reports empty arguments. Since case order comes from a
// Go map, a policy case can land ahead of another case that runs the same
// binary. Delete this once the agent releases the UID itself.
func releaseLeakedBinaryUIDs(tb testing.TB, binaries ...string) {
	tb.Helper()
	tb.Cleanup(func() {
		path := filepath.Join(bpf.MapPrefixPath(), "process_tree_binary_uid_map")
		m, err := ebpf.LoadPinnedMap(path, nil)
		require.NoError(tb, err, "opening process_tree_binary_uid_map")
		defer m.Close()

		for _, binary := range binaries {
			var key binaryUIDKey
			copy(key.binary[:], binary)
			// The uidMap memo in pkg/model/datapath can short-circuit
			// GetBinaryId, and the map is an LRU, so the entry may be gone.
			if err := m.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				tb.Errorf("deleting the binary uid entry for %q: %v", binary, err)
			}
		}
	})
}
