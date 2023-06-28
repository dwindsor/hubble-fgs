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
	"sync"
	"syscall"
	"time"

	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	fm "github.com/isovalent/hubble-fgs/pkg/sensors/file/utils"
)

var (
	hostMntNs       = flag.Uint("hostMntNs", 0, "host mnt namespace to check that the scanner is indeed running on the host mount namespace (sanity check).")
	scannerFifoPath = flag.String("scannerFifoPath", "", "path to create the scanner FIFO (for communication with the agent)")
	runtimeEndpoint = flag.String("runtimeEndpoint", "", "custom container runtime endpoint (for containerd or cri-o)")
	debug           = flag.Bool("debug", false, "Enable debug messages. Equivalent to '--log-level=debug'")
	logLevel        = flag.String("logLevel", "info", "Set log level")
	logFormat       = flag.String("logFormat", "text", "Set log format")
	help            = flag.Bool("help", false, "Show help")
)

var stopChan = make(chan os.Signal, 2)
var containerRuntimeEndpoint = ""

type rpcRunner interface {
	Run()
}

var runnerChan chan rpcRunner

type FsScannerRpc struct{}

type rpcInit struct {
	arg  *fm.FsScannerInit
	done chan error
}

func (r rpcInit) Run() {
	err := tracingPolicyInit(r.arg)
	if r.done != nil {
		r.done <- err
	}
}

func (f *FsScannerRpc) TracingPolicyInit(args *fm.FsScannerInit, _ *struct{}) error {
	r := rpcInit{
		arg:  args,
		done: make(chan error),
	}

	select {
	case runnerChan <- r:
		select { // wait for operation to complete
		case err := <-r.done:
			return err
		case <-time.After(10 * time.Minute):
			return fmt.Errorf("op TracingPolicyInit timed out")
		}
	default:
		return fmt.Errorf("runnerChan is full")
	}
}

type rpcRename struct {
	arg *fm.FsScannerRename
}

func (r rpcRename) Run() {
	renameDir(r.arg)
}

func (f *FsScannerRpc) RenameDir(args *fm.FsScannerRename, _ *struct{}) error {
	r := rpcRename{
		arg: args,
	}

	select {
	case runnerChan <- r:
		return nil // do not wait for operation to complete
	default:
		return fmt.Errorf("runnerChan is full")
	}
}

type rpcContainerInit struct {
	arg  *fm.FsScannerContainerInit
	done chan error
}

func (r rpcContainerInit) Run() {
	err := tracingPolicyContainerInit(r.arg)
	if r.done != nil {
		r.done <- err
	}
}

func (f *FsScannerRpc) TracingPolicyContainerInit(args *fm.FsScannerContainerInit, _ *struct{}) error {
	r := rpcContainerInit{
		arg:  args,
		done: make(chan error),
	}

	select {
	case runnerChan <- r:
		select { // wait for operation to complete
		case err := <-r.done:
			return err
		case <-time.After(10 * time.Minute):
			return fmt.Errorf("op TracingPolicyContainerInit timed out")
		}
	default:
		return fmt.Errorf("runnerChan is full")
	}
}

type rpcContainerDestroy struct {
	arg  *fm.FsScannerContainerDestroy
	done chan error
}

func (r rpcContainerDestroy) Run() {
	err := tracingPolicyContainerDestroy(r.arg)
	if r.done != nil {
		r.done <- err
	}
}

func (f *FsScannerRpc) TracingPolicyContainerDestroy(args *fm.FsScannerContainerDestroy, _ *struct{}) error {
	r := rpcContainerDestroy{
		arg:  args,
		done: make(chan error),
	}

	select {
	case runnerChan <- r:
		select { // wait for operation to complete
		case err := <-r.done:
			return err
		case <-time.After(10 * time.Minute):
			return fmt.Errorf("op TracingPolicyContainerDestroy timed out")
		}
	default:
		return fmt.Errorf("runnerChan is full")
	}
}

func (f *FsScannerRpc) Terminate(_, _ *struct{}) error {
	stopChan <- syscall.SIGTERM
	return nil
}

func tracingPolicyInit(args *fm.FsScannerInit) error {
	maps, cleanup, err := fm.OpenFIMMaps(args.MapDir, args.PinPath)
	if err != nil {
		return err
	}
	defer cleanup()

	logger.GetLogger().Info("fim: Adding host files")

	locFn := func(v *fileapi.HashMapFileVal) {
		v.LocationFlags = fileapi.HOST_FILE
	}

	for i, p := range args.Spec.Paths {
		if fNum, dNum, err := fm.WalkPathRaw(p, uint32(i), maps, fm.AddToMap, fm.FilterMatch, false, locFn); err != nil {
			logger.GetLogger().WithField("path", p).WithError(err).Warnf("Adding files/directories failed")
		} else {
			logger.GetLogger().WithField("path", p).Infof("Added %d file(s) and %d directorie(s)", fNum, dNum)
		}
	}

	for _, p := range args.Spec.PathsExclude {
		if fNum, dNum, err := fm.WalkPathRaw(p, 0, maps, fm.AddToMap, fm.FilterIgnore, false, locFn); err != nil {
			logger.GetLogger().WithField("path", p).WithError(err).Warnf("Excluding files/directories failed")
		} else {
			logger.GetLogger().WithField("path", p).Infof("Excluded %d file(s) and %d directorie(s)", fNum, dNum)
		}
	}

	return nil
}

func renameDir(args *fm.FsScannerRename) error {
	maps, cleanup, err := fm.OpenFIMMaps(args.MapDir, args.PinPath)
	if err != nil {
		return err
	}
	defer cleanup()

	// this should always be prefix-free
	containerID := fm.RemoveContainerIdPrefix(args.ContainerID)

	locFn := func(v *fileapi.HashMapFileVal) {
		if containerID == "" {
			v.LocationFlags = fileapi.HOST_FILE
		} else {
			var cid [64]byte
			copy(cid[:], containerID)
			v.ContainerID = cid
			v.LocationFlags = fileapi.CONTAINER_FILE
		}
	}

	if fNum, dNum, err := fm.WalkPathRaw(args.Path, args.RuleID, maps, args.Op, args.Action, true, locFn); err != nil {
		logger.GetLogger().WithField("path", args.Path).WithError(err).Warnf("Renaming files/directories failed")
	} else {
		logger.GetLogger().WithField("path", args.Path).Infof("Renamed %d file(s) and %d directorie(s)", fNum, dNum)
	}
	return nil
}

func chroot(path string) (func() error, error) {
	root, err := os.Open("/")
	if err != nil {
		return nil, fmt.Errorf("os.Open root: %w", err)
	}
	if err := syscall.Chroot(path); err != nil {
		root.Close()
		return nil, fmt.Errorf("syscall.Chroot to %s: %w", path, err)
	}
	return func() error {
		defer root.Close()
		if err := root.Chdir(); err != nil {
			return fmt.Errorf("root.Chdir to root: %w", err)
		}
		if err := syscall.Chroot("."); err != nil {
			return fmt.Errorf("syscall.Chroot to cwd: %w", err)
		}
		return nil
	}, nil
}

func tracingPolicyContainerInit(args *fm.FsScannerContainerInit) error {
	if len(args.Spec) != len(args.PinPath) {
		return fmt.Errorf("TracingPolicyContainerInit: spec and pinpath arrays have different lengths")
	}

	for i := 0; i < len(args.PinPath); i++ {
		// check if we care about this namespace
		if !fm.MatchPodSelector(args.Spec[i].PodSelector, args.PodNs, args.PodName) {
			continue
		}

		logger.GetLogger().WithField("ns", args.PodNs).WithField("app", args.PodName).WithField("cid", args.ContainerID).Info("fim: Adding container files")

		maps, cleanup, err := fm.OpenFIMMaps(args.MapDir, args.PinPath[i])
		if err != nil {
			return fmt.Errorf("OpenFIMMaps(%s, %s): %w", args.MapDir, args.PinPath[i], err)
		}
		defer cleanup()

		rootDir := args.RootDir
		if rootDir == "" {
			rootDir, err = fm.ContainerIdToRootFs(args.ContainerID, containerRuntimeEndpoint)
			if err != nil {
				return fmt.Errorf("failed to resolve container rootDir: %w", err)
			}
		}
		containerID := fm.RemoveContainerIdPrefix(args.ContainerID)

		locFn := func(v *fileapi.HashMapFileVal) {
			v.LocationFlags = fileapi.CONTAINER_FILE
			copy(v.ContainerID[:], []byte(containerID))
		}

		// enter chroot
		exit, err := chroot(rootDir)
		if err != nil {
			return fmt.Errorf("chroot to %s: %w", rootDir, err)
		}

		for i, p := range args.Spec[i].Paths {
			if fNum, dNum, err := fm.WalkPathRaw(p, uint32(i), maps, fm.AddToMap, fm.FilterMatch, false, locFn); err != nil {
				logger.GetLogger().WithField("path", p).WithField("containerID", containerID).WithError(err).Warnf("Adding files/directories failed")
			} else {
				logger.GetLogger().WithField("path", p).WithField("containerID", containerID).Infof("Added %d file(s) and %d directorie(s)", fNum, dNum)
			}
		}

		for _, p := range args.Spec[i].PathsExclude {
			if fNum, dNum, err := fm.WalkPathRaw(p, 0, maps, fm.AddToMap, fm.FilterIgnore, false, locFn); err != nil {
				logger.GetLogger().WithField("path", p).WithField("containerID", containerID).WithError(err).Warnf("Excluding files/directories failed")
			} else {
				logger.GetLogger().WithField("path", p).WithField("containerID", containerID).Infof("Excluded %d file(s) and %d directorie(s)", fNum, dNum)
			}
		}

		// exit from the chroot
		if err := exit(); err != nil {
			return fmt.Errorf("exit from chroot: %w", err)
		}

	}
	return nil
}

func tracingPolicyContainerDestroy(args *fm.FsScannerContainerDestroy) error {
	containerID := fm.RemoveContainerIdPrefix(args.ContainerID)
	for _, pinPath := range args.PinPath {
		maps, cleanup, err := fm.OpenFIMMaps(args.MapDir, pinPath)
		if err != nil {
			return err
		}
		defer cleanup()

		if err := fm.RemoveContainerEntries(maps, containerID); err != nil {
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

	if !isFlagPassed("hostMntNs") {
		logger.GetLogger().Warnf("hostMntNs flag is not passed in hubble-fgs-fs-scanner")
		os.Exit(1)
	}

	if !isFlagPassed("scannerFifoPath") {
		logger.GetLogger().Warnf("scannerFifoPath flag is not passed in hubble-fgs-fs-scanner")
		os.Exit(1)
	}

	if isFlagPassed("runtimeEndpoint") {
		containerRuntimeEndpoint = *runtimeEndpoint
		logger.GetLogger().WithField("endpoint", containerRuntimeEndpoint).Info("fim: Using custom container runtime endpoint")
	} else {
		logger.GetLogger().Info("fim: Using default runtime endpoints")
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

	// start executor goroutine
	runnerChan = make(chan rpcRunner, 128)
	var runnerWg sync.WaitGroup
	runnerWg.Add(1)
	go func() {
		for {
			r, ok := <-runnerChan
			if ok {
				r.Run()
			} else { // channel is closed
				runnerWg.Done()
				return
			}
		}
	}()

	go rpc.Accept(listener)

	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	<-stopChan

	close(runnerChan) // close runnerChan
	runnerWg.Wait()   // wait for executor goroutine to finish execution
}
