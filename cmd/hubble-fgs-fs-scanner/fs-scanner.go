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
#include <errno.h>
#include <stdlib.h>
#include <string.h>

int open_ret = -1;
int open_errno = 0;
int setns_ret = -1;
int setns_errno = 0;

__attribute__((constructor)) void enter_host_mnt_ns(void) {
	char *env_path, mnt_ns_path[256] = { 0 };
	int fd;

	strcpy(mnt_ns_path, "/procRoot/1/ns/mnt");
	env_path = getenv("TETRAGON_PROCFS");
	if (env_path) {
		snprintf(mnt_ns_path, 255, "%s/1/ns/mnt", env_path);
	}

	fd = open(mnt_ns_path, O_RDONLY);
	if (fd == -1) {
		// If /procRoot does not exist we run in host mode.
		// In that case, it is valid for the open call to fail
		// as there is no need to take any further action
		// (we are already in the host mnt namespace).
		if (errno == ENOENT) {
			open_ret = 0;
			setns_ret = 0;
			return;
		}
		open_ret = fd;
		open_errno = errno;
		return;
	}
	open_ret = 0;

	setns_ret = setns(fd, 0);
	if (setns_ret == -1)
		setns_errno = errno;
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

	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	fm "github.com/isovalent/hubble-fgs/pkg/sensors/file/utils"
)

var (
	hostMntNs       = flag.Uint("hostMntNs", 0, "host mnt namespace to check that the scanner is indeed running on the host mount namespace (sanity check).")
	scannerFifoPath = flag.String("scannerFifoPath", "", "path to create the scanner FIFO (for communication with the agent)")
	debug           = flag.Bool("debug", false, "Enable debug messages. Equivalent to '--log-level=debug'")
	logLevel        = flag.String("logLevel", "info", "Set log level")
	logFormat       = flag.String("logFormat", "text", "Set log format")
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

	locFn := func(v *fileapi.HashMapFileVal) {
		v.LocationFlags = fileapi.HOST_FILE
	}

	for _, p := range args.Spec.Paths {
		if fNum, dNum, err := fm.WalkPathRaw(p, maps, fm.AddToMap, fm.FilterMatch, false, locFn); err != nil {
			logger.GetLogger().WithField("path", p).WithError(err).Warnf("Adding files/directories failed")
		} else {
			logger.GetLogger().WithField("path", p).Infof("Added %d file(s) and %d directorie(s)", fNum, dNum)
		}
	}

	for _, p := range args.Spec.PathsExclude {
		if fNum, dNum, err := fm.WalkPathRaw(p, maps, fm.AddToMap, fm.FilterIgnore, false, locFn); err != nil {
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

	locFn := func(v *fileapi.HashMapFileVal) {
		if args.ContainerID == "" {
			v.LocationFlags = fileapi.HOST_FILE
		} else {
			var cid [64]byte
			copy(cid[:], args.ContainerID)
			v.ContainerID = cid
			v.LocationFlags = fileapi.CONTAINER_FILE
		}
	}

	if fNum, dNum, err := fm.WalkPathRaw(args.Path, maps, args.Op, args.Action, true, locFn); err != nil {
		logger.GetLogger().WithField("path", args.Path).WithError(err).Warnf("Renaming files/directories failed")
	} else {
		logger.GetLogger().WithField("path", args.Path).Infof("Renamed %d file(s) and %d directorie(s)", fNum, dNum)
	}
	return nil
}

func chroot(path string) (func() error, error) {
	root, err := os.Open("/")
	if err != nil {
		return nil, err
	}
	if err := syscall.Chroot(path); err != nil {
		root.Close()
		return nil, err
	}
	return func() error {
		defer root.Close()
		if err := root.Chdir(); err != nil {
			return err
		}
		return syscall.Chroot(".")
	}, nil
}

func (f *FsScannerRpc) TracingPolicyContainerInit(args *fm.FsScannerContainerInit, _ *struct{}) error {
	if len(args.Spec) != len(args.PinPath) {
		return fmt.Errorf("TracingPolicyContainerInit: spec and pinpath arrays have different lengths")
	}

	for i := 0; i < len(args.PinPath); i++ {
		maps, cleanup, err := fm.OpenFIMMaps(args.MapDir, args.PinPath[i])
		if err != nil {
			return err
		}
		defer cleanup()

		locFn := func(v *fileapi.HashMapFileVal) {
			v.LocationFlags = fileapi.CONTAINER_FILE
			copy(v.ContainerID[:], []byte(args.ContainerID))
		}

		// enter chroot
		exit, err := chroot(args.RootDir)
		if err != nil {
			return err
		}

		for _, p := range args.Spec[i].Paths {
			if fNum, dNum, err := fm.WalkPathRaw(p, maps, fm.AddToMap, fm.FilterMatch, false, locFn); err != nil {
				logger.GetLogger().WithField("path", p).WithField("containerID", args.ContainerID).WithError(err).Warnf("Adding files/directories failed")
			} else {
				logger.GetLogger().WithField("path", p).WithField("containerID", args.ContainerID).Infof("Added %d file(s) and %d directorie(s)", fNum, dNum)
			}
		}

		for _, p := range args.Spec[i].PathsExclude {
			if fNum, dNum, err := fm.WalkPathRaw(p, maps, fm.AddToMap, fm.FilterIgnore, false, locFn); err != nil {
				logger.GetLogger().WithField("path", p).WithField("containerID", args.ContainerID).WithError(err).Warnf("Excluding files/directories failed")
			} else {
				logger.GetLogger().WithField("path", p).WithField("containerID", args.ContainerID).Infof("Excluded %d file(s) and %d directorie(s)", fNum, dNum)
			}
		}

		// exit from the chroot
		if err := exit(); err != nil {
			return err
		}

	}
	return nil
}

func (f *FsScannerRpc) TracingPolicyContainerDestroy(args *fm.FsScannerContainerDestroy, _ *struct{}) error {
	for _, pinPath := range args.PinPath {
		maps, cleanup, err := fm.OpenFIMMaps(args.MapDir, pinPath)
		if err != nil {
			return err
		}
		defer cleanup()

		if err := fm.RemoveContainerEntries(maps, args.ContainerID); err != nil {
			return err
		}
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

	logL := ""
	if isFlagPassed("logLevel") {
		logL = *logLevel
	}

	logF := ""
	if isFlagPassed("logFormat") {
		logF = *logFormat
	}

	// setup logging
	o := make(map[string]string)
	logger.PopulateLogOpts(o, logL, logF)
	if err := logger.SetupLogging(o, *debug); err != nil {
		log.Fatal(err)
	}

	// open failed due to a different error than "No such file or directory"
	if C.open_ret == -1 {
		logger.GetLogger().WithField("errno", C.open_errno).Warnf("open failed in hubble-fgs-fs-scanner")
		os.Exit(1)
	}

	if C.setns_ret == -1 {
		logger.GetLogger().WithField("errno", C.setns_errno).Warnf("setns failed in hubble-fgs-fs-scanner")
		os.Exit(1)
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
