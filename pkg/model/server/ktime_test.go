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

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// epoch is an arbitrary fixed wall-clock time used as the converter base in
// deterministic tests. Using a fixed value avoids any dependency on the
// system clock and makes failures easy to reproduce.
var epoch = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

func TestKtimeConvert_BasicArithmetic(t *testing.T) {
	c := ktimeConverter{base: epoch}

	const kt uint64 = 500_000_000 // 500 ms expressed in nanoseconds
	got := c.convert(kt)
	require.NotNil(t, got)

	want := epoch.Add(time.Duration(kt)).Truncate(time.Microsecond)
	assert.Equal(t, want, *got)
}

func TestKtimeConvert_ZeroKtimeReturnsNil(t *testing.T) {
	c := ktimeConverter{base: epoch}
	assert.Nil(t, c.convert(0))
}

func TestKtimeConvert_ZeroBaseReturnsNil(t *testing.T) {
	c := ktimeConverter{} // zero value; base.IsZero() == true
	assert.Nil(t, c.convert(1_000_000_000))
}

func TestKtimeConvert_MicrosecondTruncation(t *testing.T) {
	c := ktimeConverter{base: epoch}

	// Choose a ktime with a sub-microsecond remainder so that truncation is
	// observable: 1µs + 500ns → 1µs after Truncate(µs).
	const kt uint64 = 1_500 // 1500 ns = 1 µs + 500 ns
	got := c.convert(kt)
	require.NotNil(t, got)

	// The nanosecond component below the microsecond boundary must be zero.
	assert.Equal(t, 0, got.Nanosecond()%int(time.Microsecond),
		"sub-microsecond precision should be truncated")

	// Confirm the value rounds down, not up.
	want := epoch.Add(time.Duration(kt)).Truncate(time.Microsecond)
	assert.Equal(t, want, *got)
}

func TestKtimeConvert_Monotonicity(t *testing.T) {
	c := ktimeConverter{base: epoch}

	const k1 uint64 = 1_000_000_000  // 1 s
	const k2 uint64 = 2_000_000_000  // 2 s
	const k3 uint64 = 10_000_000_000 // 10 s

	t1 := c.convert(k1)
	t2 := c.convert(k2)
	t3 := c.convert(k3)

	require.NotNil(t, t1)
	require.NotNil(t, t2)
	require.NotNil(t, t3)

	assert.True(t, t1.Before(*t2), "convert(k1) should be before convert(k2)")
	assert.True(t, t2.Before(*t3), "convert(k2) should be before convert(k3)")
}

func TestKtimeConvert_ConsistencyWithinTick(t *testing.T) {
	// One converter shared across multiple conversions, just like production
	// where a single ktimeConverter is constructed once per tick.
	c := ktimeConverter{base: epoch}

	ktimes := []uint64{
		100_000_000,
		200_000_000,
		300_000_000,
		1_000_000_000,
		5_000_000_000,
	}

	results := make([]*time.Time, len(ktimes))
	for i, kt := range ktimes {
		results[i] = c.convert(kt)
		require.NotNil(t, results[i])
	}

	// Relative ordering of results must match relative ordering of inputs.
	for i := 1; i < len(results); i++ {
		assert.True(t, results[i-1].Before(*results[i]),
			"result[%d] should be before result[%d]", i-1, i)
	}

	// Verify the spacing between consecutive results exactly matches the
	// spacing between the corresponding ktime values. Because all conversions
	// use the same base, the deltas should be identical.
	for i := 1; i < len(results); i++ {
		wantDelta := time.Duration(ktimes[i] - ktimes[i-1])
		gotDelta := results[i].Sub(*results[i-1])
		assert.Equal(t, wantDelta, gotDelta,
			"delta between results[%d] and results[%d] should equal ktime delta", i-1, i)
	}
}

func TestKtimeConvert_LargeKtime(t *testing.T) {
	c := ktimeConverter{base: epoch}

	// ~1 year expressed in nanoseconds: 365 * 24 * 3600 * 1e9
	const oneYearNs uint64 = 365 * 24 * 3600 * 1_000_000_000

	got := c.convert(oneYearNs)
	require.NotNil(t, got, "large ktime should not produce nil")

	// The result should be roughly epoch + 1 year.
	want := epoch.Add(time.Duration(oneYearNs)).Truncate(time.Microsecond)
	assert.Equal(t, want, *got)

	// Sanity: the result must be in a plausible range (not the zero time, not
	// absurdly far in the future).
	assert.False(t, got.IsZero())
	assert.True(t, got.After(epoch))
}
