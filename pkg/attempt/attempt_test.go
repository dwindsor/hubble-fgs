// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package attempt

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestConcurrentSubAttempts completes sub-attempts of the same parent from
// multiple goroutines. Run with -race to catch unsynchronized access.
func TestConcurrentSubAttempts(t *testing.T) {
	const n = 16

	log := NewLog()
	parent := log.NewAttempt("parent")

	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			sub := parent.NewAttempt("sub").WithInfo("k", "v")
			var err error
			if i%2 == 0 {
				err = errors.New("fail")
			}
			require.NoError(t, sub.Complete(err))
		})
	}
	wg.Wait()

	require.NoError(t, parent.Complete(nil))

	atts := log.Attempts()
	entry := atts.LastEntry()
	require.NotNil(t, entry)
	require.Len(t, entry.Attempts, n)
	require.Equal(t, n/2, parent.errCnt)
}
