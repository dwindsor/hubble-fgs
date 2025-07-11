//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package testutils

import (
	"os/exec"
	"sync"
)

var onceCheckNetIOUring = sync.OnceValue(checkNetIOUring)

// NetIOUringAvailable checks if the kernel supports net io_uring. Returns false in case of error.
func NetIOUringAvailable() bool {
	return onceCheckNetIOUring()
}

func checkNetIOUring() bool {
	testProg := RepoRootPath("contrib/tester-progs/io_uring/net_iouring_check")
	cmdTest := exec.Command(testProg)
	err := cmdTest.Run()
	return err == nil
}
