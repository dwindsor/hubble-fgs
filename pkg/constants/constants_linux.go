// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package constants

import (
	"syscall"

	"github.com/cilium/tetragon/pkg/sensors/tracing"
	"golang.org/x/sys/unix"
)

const (
	RUSAGE_SELF         = syscall.RUSAGE_SELF
	RUSAGE_THREAD       = syscall.RUSAGE_THREAD
	O_APPEND            = unix.O_APPEND
	O_ASYNC             = unix.O_ASYNC
	O_CLOEXEC           = unix.O_CLOEXEC
	O_CREAT             = unix.O_CREAT
	O_DIRECT            = unix.O_DIRECT
	O_DIRECTORY         = unix.O_DIRECTORY
	O_TMPFILE           = unix.O_TMPFILE
	O_DSYNC             = unix.O_DSYNC
	O_EXCL              = unix.O_EXCL
	O_NOATIME           = unix.O_NOATIME
	O_NOCTTY            = unix.O_NOCTTY
	O_NOFOLLOW          = unix.O_NOFOLLOW
	O_NONBLOCK          = unix.O_NONBLOCK // or O_NDELAY
	O_PATH              = unix.O_PATH
	O_SYNC              = unix.O_SYNC // or O_FSYNC
	O_TRUNC             = unix.O_TRUNC
	O_ACCMODE           = unix.O_ACCMODE
	O_RDONLY            = unix.O_RDONLY
	O_RDWR              = unix.O_RDWR
	O_WRONLY            = unix.O_WRONLY
	Is32Bit             = tracing.Is32Bit
	IPPROTO_ICMP        = unix.IPPROTO_ICMP
	BPF_TCP_ESTABLISHED = unix.BPF_TCP_ESTABLISHED
	BPF_TCP_LISTEN      = unix.BPF_TCP_LISTEN
	BPF_TCP_CLOSE       = unix.BPF_TCP_CLOSE
	IPPROTO_RAW         = unix.IPPROTO_RAW
	CLOCK_MONOTONIC     = unix.CLOCK_MONOTONIC
)
