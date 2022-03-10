//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package kernels

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKernelStringToNumeric(t *testing.T) {
	v1 := KernelStringToNumeric("5.17.0")
	v2 := KernelStringToNumeric("5.17.0+")
	v3 := KernelStringToNumeric("5.17.0-foobar")
	assert.Equal(t, v1, v2)
	assert.Equal(t, v2, v3)

	v1 = KernelStringToNumeric("5.4.144+")
	v2 = KernelStringToNumeric("5.10.0")
	assert.Less(t, v1, v2)

	v1 = KernelStringToNumeric("5")
	v2 = KernelStringToNumeric("5.4")
	v3 = KernelStringToNumeric("5.4.0")
	v4 := KernelStringToNumeric("5.4.1")
	assert.Less(t, v1, v2)
	assert.Equal(t, v2, v3)
	assert.Less(t, v2, v4)

	v1 = KernelStringToNumeric("4")
	v2 = KernelStringToNumeric("4.19")
	v3 = KernelStringToNumeric("5.19")
	assert.Less(t, v1, v2)
	assert.Less(t, v2, v3)
	assert.Less(t, v1, v3)
}

func TestGetKernelVersion(t *testing.T) {
	ver, verStr, err := GetKernelVersion("", "/proc")
	assert.Nil(t, err)
	assert.EqualValues(t, KernelStringToNumeric(verStr), ver)
}
