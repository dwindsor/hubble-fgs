//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package mandate

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPolName(t *testing.T) {
	for _, id := range []uint{1, 2324} {
		n := mandatePolName("pizza", id)
		orig, ok := OrigPolName(n)
		require.True(t, ok, fmt.Sprintf("could not match %s", n))
		require.Equal(t, "pizza", orig)
	}

	_, ok := OrigPolName("pizza")
	require.False(t, ok)
}
