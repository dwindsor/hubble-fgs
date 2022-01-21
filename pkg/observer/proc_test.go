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

	test3 := "cri-containerd-123456789abcdef"
	offsetValue3 := 15

	s, i := procsDockerIdOffset(test1)
	assert.Equal(t, s, test1, "Expect input == output")
	assert.Equal(t, i, 0, "Expect zero offset")

	s, i = procsDockerIdOffset(test2)
	assert.Equal(t, test1, s, "Expect output is test1")
	assert.Equal(t, offsetValue, i, "Expect docker- offset")

	s, i = procsDockerIdOffset(test3)
	assert.Equal(t, test1, s, "Expect output is test3")
	assert.Equal(t, offsetValue3, i, "Expect docker- offset")
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
	d, i := procsFindDockerId(p)
	assert.Equal(t, i, 0, "Docker offset wrong")
	assert.Equal(t, d, "ae7a1981e064c217035e0b23979c8de", "DockerId wrong")

	p = "4:pids:/kubepods/burstable/pod1399d9c7-c86f-4371-8568-07b3d32258a4/91f2457fb4c2b1356eefc7bace36532f5eb3d354804bb2cff787ea321320b5a5"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 0, "Docker offset wrong")
	assert.Equal(t, d, "91f2457fb4c2b1356eefc7bace36532", "DockerId wrong")

	p = "4:pids:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podeb052b63_ea96_4728_ab4a_64ab3babccd7.slice/cri-containerd-5694f82f44168cc048e014ae14d1b0c8ef673bec49f329dc169911ea638f63c2.scope"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 15, "Docker offset wrong")
	assert.Equal(t, d, "5694f82f44168cc048e014ae14d1b0c", "DockerId wrong")

	p = "4:pids:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podeb052b63_ea96_4728_ab4a_64ab3babccd7.slice/docker-5694f82f44168cc048e014ae14d1b0c8ef673bec49f329dc169911ea638f63c2.scope"
	d, i = procsFindDockerId(p)
	assert.Equal(t, i, 7, "Docker offset wrong")
	assert.Equal(t, d, "5694f82f44168cc048e014ae14d1b0c", "DockerId wrong")
}
