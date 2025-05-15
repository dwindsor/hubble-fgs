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
)

const (
	RUSAGE_SELF         = 0x0
	RUSAGE_THREAD       = 0x1
	O_APPEND            = syscall.O_APPEND
	O_ASYNC             = syscall.O_ASYNC
	O_CLOEXEC           = syscall.O_CLOEXEC
	O_CREAT             = syscall.O_CREAT
	O_DIRECT            = 0x4000
	O_DIRECTORY         = 0x10000
	O_TMPFILE           = 0x410000
	O_DSYNC             = 0x11000
	O_EXCL              = syscall.O_EXCL
	O_NOATIME           = 0x40000
	O_NOCTTY            = syscall.O_NOCTTY
	O_NOFOLLOW          = 0x20000
	O_NONBLOCK          = syscall.O_NONBLOCK
	O_PATH              = 0x200000
	O_SYNC              = syscall.O_SYNC
	O_TRUNC             = syscall.O_TRUNC
	O_ACCMODE           = 0x3
	O_RDONLY            = syscall.O_RDONLY
	O_RDWR              = syscall.O_RDWR
	O_WRONLY            = syscall.O_WRONLY
	Is32Bit             = 0x80000000
	IPPROTO_ICMP        = 0x1
	BPF_TCP_ESTABLISHED = 0x1
	BPF_TCP_LISTEN      = 0xa
	BPF_TCP_CLOSE       = 0x7
	IPPROTO_RAW         = 0xff
	CLOCK_MONOTONIC     = 0x1
)
