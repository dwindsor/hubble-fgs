// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package mandate

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInherit(t *testing.T) {
	type tc struct {
		p string // parent
		c string // child
		e string // expected
	}

	testCases := []tc{
		{
			p: "https://tetragon-mandate-test.s3.us-west-2.amazonaws.com/mandate.yaml",
			c: "policies/foo.yaml",
			e: "https://tetragon-mandate-test.s3.us-west-2.amazonaws.com/policies/foo.yaml",
		},
	}

	for _, tc := range testCases {
		p, err := url.Parse(tc.p)
		require.NoError(t, err)
		c, err := url.Parse(tc.c)
		require.NoError(t, err)
		inheritURL(c, p)
		require.Equal(t, tc.e, c.String())
	}
}
