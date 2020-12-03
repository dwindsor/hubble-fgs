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
