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
	"log"
	"net"
	"net/rpc"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/tetragon/pkg/logger"

	fm "github.com/isovalent/hubble-fgs/pkg/sensors/file/utils"
)

var (
	hostMntNs       = flag.Uint("hostMntNs", 0, "host mnt namespace to check that the scanner is indeed running on the host mount namespace (sanity check).")
	scannerFifoPath = flag.String("scannerFifoPath", "", "path to create the scanner FIFO (for communication with the agent)")
	help            = flag.Bool("help", false, "Show help")
)

var stopChan = make(chan os.Signal, 2)

type FsScannerRpc struct{}

func (f *FsScannerRpc) Terminate(_, _ *struct{}) error {
	stopChan <- syscall.SIGTERM
	return nil
}

func (f *FsScannerRpc) TracingPolicyInit(args *fm.FsScannerInit, _ *struct{}) error {
	maps, cleanup, err := fm.OpenFIMMaps(args.MapDir, args.PinPath)
	if err != nil {
		return err
	}
	defer cleanup()

	for _, p := range args.Spec.Paths {
		if fNum, dNum, err := fm.WalkPathRaw(p, maps, fm.AddToMap, fm.FilterMatch, false); err != nil {
			logger.GetLogger().WithField("path", p).WithError(err).Warnf("Adding files/directories failed")
		} else {
			logger.GetLogger().WithField("path", p).Infof("Added %d file(s) and %d directorie(s)", fNum, dNum)
		}
	}

	for _, p := range args.Spec.PathsExclude {
		if fNum, dNum, err := fm.WalkPathRaw(p, maps, fm.AddToMap, fm.FilterIgnore, false); err != nil {
			logger.GetLogger().WithField("path", p).WithError(err).Warnf("Excluding files/directories failed")
		} else {
			logger.GetLogger().WithField("path", p).Infof("Excluded %d file(s) and %d directorie(s)", fNum, dNum)
		}
	}

	return nil
}

func (f *FsScannerRpc) RenameDir(args *fm.FsScannerRename, _ *struct{}) error {
	maps, cleanup, err := fm.OpenFIMMaps(args.MapDir, args.PinPath)
	if err != nil {
		return err
	}
	defer cleanup()

	if fNum, dNum, err := fm.WalkPathRaw(args.Path, maps, args.Op, args.Action, true); err != nil {
		logger.GetLogger().WithField("path", args.Path).WithError(err).Warnf("Renaming files/directories failed")
	} else {
		logger.GetLogger().WithField("path", args.Path).Infof("Renamed %d file(s) and %d directorie(s)", fNum, dNum)
	}
	return nil
}

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

	if !isFlagPassed("hostMntNs") {
		logger.GetLogger().Warnf("hostMntNs flag is not passed in hubble-fgs-fs-scanner")
		os.Exit(1)
	}

	if !isFlagPassed("scannerFifoPath") {
		logger.GetLogger().Warnf("scannerFifoPath flag is not passed in hubble-fgs-fs-scanner")
		os.Exit(1)
	}

	inum, err := GetMntNsInode()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("GetPidNsInode")
		os.Exit(2)
	}
	if inum != *hostMntNs {
		logger.GetLogger().Warnf("Mnt namespace of hubble-fgs-fs-scanner (%d) does not match host mnt namespace", inum)
		os.Exit(3)
	}

	fs := new(FsScannerRpc)
	rpc.Register(fs)

	listener, err := net.Listen("unix", *scannerFifoPath)
	if err != nil {
		log.Fatalf("unable to listen: path: %s error: %s", *scannerFifoPath, err)
	}
	defer os.Remove(*scannerFifoPath)
	go rpc.Accept(listener)

	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	<-stopChan
}
