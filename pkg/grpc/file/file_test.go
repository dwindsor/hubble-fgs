//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

// go test -gcflags="" -c ./pkg/grpc/file/ -o go-tests/grpc-file.test
// ./go-tests/grpc-file.test

package file

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestOpenFlagsParsing(t *testing.T) {
	s := getOpenFlags(unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_DIRECTORY)
	assert.Equal(t, len(s), 4, "flags:%s", s)
	assert.Contains(t, s, "O_RDONLY")
	assert.Contains(t, s, "O_NONBLOCK")
	assert.Contains(t, s, "O_CLOEXEC")
	assert.Contains(t, s, "O_DIRECTORY")

	s = getOpenFlags(unix.O_RDONLY | unix.O_DIRECTORY)
	assert.Equal(t, len(s), 2, "flags:%s", s)
	assert.Contains(t, s, "O_RDONLY")
	assert.Contains(t, s, "O_DIRECTORY")

	s = getOpenFlags(unix.O_RDWR | unix.O_TMPFILE)
	assert.Equal(t, len(s), 3, "flags:%s", s)
	assert.Contains(t, s, "O_RDWR")
	assert.Contains(t, s, "O_TMPFILE")
	assert.Contains(t, s, "O_DIRECTORY") // O_TMPFILE also implies and O_DIRECTORY: https://elixir.bootlin.com/linux/v6.8/source/include/uapi/asm-generic/fcntl.h#L93

	s = getOpenFlags(unix.O_WRONLY | unix.O_CREAT | unix.O_APPEND)
	assert.Equal(t, len(s), 3, "flags:%s", s)
	assert.Contains(t, s, "O_WRONLY")
	assert.Contains(t, s, "O_CREAT")
	assert.Contains(t, s, "O_APPEND")
}
