// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dnsparser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type FakeIPToIDMaps struct {
	mapCount uint32
	mapIndex uint32
}

func (m FakeIPToIDMaps) MapCount() uint32 {
	return m.mapCount
}

func (m *FakeIPToIDMaps) AppendAndPopulateNewInnerMap() error {
	m.mapCount++
	m.mapIndex++
	return nil
}

func (m *FakeIPToIDMaps) RemoveInnerMap(_ uint32) error {
	m.mapCount--
	return nil
}

func TestAllocateMapsIfNeeded(t *testing.T) {
	fakeMap := FakeIPToIDMaps{}

	// Simulate initial preallocation like in the layer3 sensor init
	IPToIDMapsToPrealloc = 10
	for range IPToIDMapsToPrealloc {
		err := fakeMap.AppendAndPopulateNewInnerMap()
		require.NoError(t, err)
	}

	// We will need a margin of 5
	IPToIDMapsMargin = 5

	// We have 10 maps, 0 used
	allocationID := uint32(8)
	// We have 10 maps, 9 used
	err := AllocateMapsIfNeeded(&fakeMap, allocationID)
	require.NoError(t, err)
	assert.EqualValues(t, 14, fakeMap.mapCount)
	assert.EqualValues(t, 14, fakeMap.mapIndex)

	// We have 14 maps, 9 used
	err = fakeMap.RemoveInnerMap(4)
	require.NoError(t, err)
	assert.EqualValues(t, 13, fakeMap.mapCount)
	assert.EqualValues(t, 14, fakeMap.mapIndex)

	// Removing doesn't reduce the used maps because we don't reuse
	// We have 13 maps, 9 used
	err = AllocateMapsIfNeeded(&fakeMap, allocationID)
	require.NoError(t, err)
	assert.EqualValues(t, 14, fakeMap.mapCount)
	assert.EqualValues(t, 15, fakeMap.mapIndex)

	// We have 14 maps, 9 used
	allocationID += 4
	// We have 14 maps, 13 used
	err = AllocateMapsIfNeeded(&fakeMap, allocationID)
	require.NoError(t, err)
	assert.EqualValues(t, 18, fakeMap.mapCount)
	assert.EqualValues(t, 19, fakeMap.mapIndex)

	// We have 18 maps, 13 used
	err = fakeMap.RemoveInnerMap(1)
	require.NoError(t, err)
	err = fakeMap.RemoveInnerMap(2)
	require.NoError(t, err)
	err = fakeMap.RemoveInnerMap(3)
	require.NoError(t, err)
	assert.EqualValues(t, 15, fakeMap.mapCount)
	assert.EqualValues(t, 19, fakeMap.mapIndex)

	// We have 15 maps, 13 used
	err = AllocateMapsIfNeeded(&fakeMap, allocationID)
	require.NoError(t, err)
	assert.EqualValues(t, 18, fakeMap.mapCount)
	assert.EqualValues(t, 22, fakeMap.mapIndex)
}
