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

package reader

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/isovalent/hubble-fgs/pkg/option"
)

func GetPidNsInode(pid uint32, nsStr string) uint32 {
	pidStr := strconv.Itoa(int(pid))
	netns := filepath.Join(option.Config.ProcFS, pidStr, "ns", nsStr)
	netStr, err := os.Readlink(netns)
	if err != nil {
		return 0
	}
	fields := strings.Split(netStr, ":")
	if len(fields) < 2 {
		return 0
	}
	inode := fields[1]
	inode = strings.TrimRight(inode, "]")
	inode = strings.TrimLeft(inode, "[")
	inodeEntry, _ := strconv.ParseUint(inode, 10, 32)
	return uint32(inodeEntry)
}
