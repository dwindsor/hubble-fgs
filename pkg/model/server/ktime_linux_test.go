// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build linux && !nok8s

package server

import (
	"testing"

	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestKtimeConvert_EquivalenceWithDecodeKtime verifies that newKtimeConverter
// and ktime.DecodeKtime produce timestamps within 1 ms of each other for the
// same ktime input. The small tolerance accounts for the wall-clock time that
// elapses between the two syscalls; it is not a precision gap in the algorithm.
func TestKtimeConvert_EquivalenceWithDecodeKtime(t *testing.T) {
	// Sample a ktime value from CLOCK_BOOTTIME right before both conversions
	// so the input is realistic (a recently-observed nanosecond counter).
	var bt unix.Timespec
	require.NoError(t, unix.ClockGettime(unix.CLOCK_BOOTTIME, &bt))
	kt := uint64(bt.Nano())

	c := newKtimeConverter()
	got := c.convert(kt)
	require.NotNil(t, got, "newKtimeConverter should produce a non-nil result")

	// DecodeKtime uses CLOCK_BOOTTIME (monotonic=false), matching newKtimeConverter.
	ref, err := ktime.DecodeKtime(int64(kt), false)
	require.NoError(t, err)

	delta := got.Sub(ref)
	if delta < 0 {
		delta = -delta
	}

	const tolerance = 1_000_000 // 1 ms in nanoseconds
	assert.Less(t, int64(delta), int64(tolerance),
		"ktimeConverter and DecodeKtime should agree within 1 ms; got delta %v", delta)
}
