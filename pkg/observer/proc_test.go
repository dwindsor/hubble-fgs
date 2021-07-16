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
package observer

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProcsDockerIdOffset(t *testing.T) {
	test1 := "123456789abcdef"
	offsetValue := 7
	test2 := "docker-123456789abcdef"

	s, i, e := procsDockerIdOffset(test1)
	assert.NoError(t, e)
	assert.Equal(t, s, test1, "Expect input == output")
	assert.Equal(t, i, 0, "Expect zero offset")

	s, i, e = procsDockerIdOffset(test2)
	assert.NoError(t, e)
	assert.Equal(t, test1, s, "Expect output is test1")
	assert.Equal(t, offsetValue, i, "Expect docker- offset")

}

func TestProcsDockerId(t *testing.T) {
	myPid := uint32(os.Getpid())

	s, i, e := procsDockerId(myPid)
	// This is not in a docker-cgroup so we have no info
	assert.Equal(t, "", s, "No cgroup info here")
	assert.Equal(t, 0, i, "Incorrect offset value")
	assert.NoError(t, e)

	// To further test we need a k8s environment unforunately. TBD
}

func TestProcsFindDockerId(t *testing.T) {
	p := "6:pids:/kubepods/besteffort/pod26ab26cd-6409-443f-a13c-fd6c231207c8/ae7a1981e064c217035e0b23979c8defd51c850d1af26fbcf148187e5b0da61c"
	d, i, _ := procsFindDockerId(p)
	assert.Equal(t, i, 0, "Docker offset wrong")
	assert.Equal(t, d, "ae7a1981e064c217035e0b23979c8de", "DockerId wrong")

	p = "4:pids:/kubepods/burstable/pod1399d9c7-c86f-4371-8568-07b3d32258a4/91f2457fb4c2b1356eefc7bace36532f5eb3d354804bb2cff787ea321320b5a5"
	d, i, _ = procsFindDockerId(p)
	assert.Equal(t, i, 0, "Docker offset wrong")
	assert.Equal(t, d, "91f2457fb4c2b1356eefc7bace36532", "DockerId wrong")

}
