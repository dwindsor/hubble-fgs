//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package file

import (
	"syscall"

	iouring "github.com/iceber/iouring-go/syscall"
)

func SupportIoUring() bool {
	params := iouring.IOURingParams{}
	fd, err := iouring.IOURingSetup(8, &params)
	if err != nil || fd == -1 {
		return false
	}
	syscall.Close(fd)
	return true
}
