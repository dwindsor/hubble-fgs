// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !windows

package perfring

import (
	"context"
	"testing"

	"github.com/cilium/tetragon/pkg/reader/notify"
	oss "github.com/cilium/tetragon/pkg/testutils/perfring"
)

//revive:disable:context-as-argument
func RunTestFreqCount[K comparable](
	t *testing.T,
	ctx context.Context,
	operations func(),
	mapFn func(notify.Message) K,
) map[K]int {
	return oss.RunTestEventReduce(t, ctx,
		operations,
		oss.FilterTestMessages,
		mapFn,
		func(m map[K]int, k K) map[K]int {
			if m == nil {
				m = make(map[K]int)
			}
			m[k]++
			return m
		},
	)
}
