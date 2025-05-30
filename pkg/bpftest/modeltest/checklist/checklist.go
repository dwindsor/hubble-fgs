// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package checklist

import (
	"fmt"
	"maps"
	"sort"

	"github.com/stretchr/testify/assert"
)

// Checklist tracks a set of items that need to be checked off during testing.
type Checklist[K comparable, V any] struct {
	items map[K]V
	name  string
}

// New creates a new Checklist from the provided map.
func New[K comparable, V any](name string, items map[K]V) *Checklist[K, V] {
	// Create a copy to avoid modifying the original map
	itemsCopy := make(map[K]V, len(items))
	maps.Copy(itemsCopy, items)

	return &Checklist[K, V]{
		items: itemsCopy,
		name:  name,
	}
}

// Check marks an item as completed by removing it from the checklist.
// Returns true if the item existed and was removed, false otherwise.
func (c *Checklist[K, V]) Check(key K) bool {
	if _, exists := c.items[key]; exists {
		delete(c.items, key)
		return true
	}
	return false
}

// Remaining returns the number of unchecked items.
func (c *Checklist[K, V]) Remaining() int {
	return len(c.items)
}

// IsComplete returns true if all items have been checked off.
func (c *Checklist[K, V]) IsComplete() bool {
	return len(c.items) == 0
}

// GetRemaining returns a copy of the remaining unchecked items.
func (c *Checklist[K, V]) GetRemaining() map[K]V {
	remaining := make(map[K]V, len(c.items))
	maps.Copy(remaining, c.items)
	return remaining
}

// AssertComplete fails the test if there are any unchecked items remaining,
// providing detailed information about what checks were missed.
func (c *Checklist[K, V]) AssertComplete(t assert.TestingT) bool {
	if ht, ok := t.(interface{ Helper() }); ok {
		ht.Helper()
	}

	if len(c.items) == 0 {
		return true
	}

	// Create a sorted list for consistent error messages
	type keyValue struct {
		key   string
		value V
	}
	var items []keyValue
	for k, v := range c.items {
		items = append(items, keyValue{key: fmt.Sprintf("%v", k), value: v})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].key < items[j].key
	})

	// Individual assertions for each missing item with details.
	// No empty assert here because it produces an ugly error message.
	// We will get an individual error for each missed item below.
	ok := assert.True(t, len(c.items) == 0, "missed %d %s check(s)", len(c.items), c.name)
	for _, item := range items {
		if isEmptyStruct(item.value) {
			assert.Fail(t, fmt.Sprintf("missed %s check for %s", c.name, item.key))
		} else {
			assert.Fail(t, fmt.Sprintf("missed %s check for %s: %v", c.name, item.key, item.value))
		}
	}
	return ok
}

// isEmptyStruct checks if a value is an empty struct (struct{})
func isEmptyStruct(v any) bool {
	switch v.(type) {
	case struct{}:
		return true
	default:
		return false
	}
}
