//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

/*
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

__attribute__((constructor)) void enter_host_mnt_ns(void) {
	int fd = open("/procRoot/1/ns/mnt", O_RDONLY);
	if (fd == -1)
		return;

	setns(fd, 0);
	close(fd);
}
*/
import "C"

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/sensors/file"
)

var (
	paths        = flag.String("paths", "", "paths separated by ':'")
	mapDir       = flag.String("mapDir", "", "directory of maps")
	checkPrefix  = flag.String("checkPrefix", "", "checkPrefix for WalkPath (should be true or false)")
	walkOp       = flag.Uint("walkOp", 0, "walkOp for WalkPath")
	filterAction = flag.Uint("filterAction", 0, "filterAction for WalkPath")
	hostMntNs    = flag.Uint("hostMntNs", 0, "host mnt namespace for sanity check")
	help         = flag.Bool("help", false, "Show help")
)

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func GetMntNsInode() (uint, error) {
	mntns := filepath.Join("/proc", "1", "ns", "mnt")
	mntStr, err := os.Readlink(mntns)
	if err != nil {
		return 0, err
	}
	fields := strings.Split(mntStr, ":")
	if len(fields) < 2 {
		return 0, fmt.Errorf("cannot parse %s in GetMntNsInode", mntStr)
	}
	inode := fields[1]
	inode = strings.TrimRight(inode, "]")
	inode = strings.TrimLeft(inode, "[")
	inodeEntry, err := strconv.ParseUint(inode, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint(inodeEntry), nil
}

func main() {
	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	l := logger.GetLogger()
	if !isFlagPassed("paths") ||
		!isFlagPassed("mapDir") ||
		!isFlagPassed("walkOp") ||
		!isFlagPassed("hostMntNs") ||
		!isFlagPassed("filterAction") ||
		!isFlagPassed("checkPrefix") {
		l.Warnf("One of more flags are not passed in fs-scanner")
		os.Exit(1)
	}

	inum, err := GetMntNsInode()
	if err != nil {
		l.WithError(err).Warn("GetPidNsInode")
		os.Exit(2)
	}
	if inum != *hostMntNs {
		l.Warnf("Mnt namespace of fs-scanner (%d) does not match host mnt namespace", inum)
		os.Exit(3)
	}

	cPrefix, err := strconv.ParseBool(*checkPrefix)
	if err != nil {
		l.Warnf("checkPrefix should be true or false (%s)", *checkPrefix)
		os.Exit(4)
	}

	pathSplit := strings.Split(*paths, ":")
	for _, p := range pathSplit {
		l.Infof("Path = %s", p)
		file.WalkPath(p, *mapDir, uint32(*walkOp), uint32(*filterAction), cPrefix)
	}

	os.Exit(0)
}
