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
	"context"
	"flag"
	"fmt"
	"io"
	"io/fs"
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

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/program"

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

var (
	// maximum time in seconds to wait for digest computation
	maxTimeoutDigestSeconds int64

	// this is the maximum size of a file that we will compute a digest
	maxFileSizeDigest int64
)

type rpcRunner interface {
	Run()
}

var runnerChan chan rpcRunner

type FsScannerRpc struct{}

type rpcDigests struct {
	arg   *fm.FsScannerDigests
	reply *map[string]string
	done  chan error
}

func (r rpcDigests) Run() {
	err := tracingPolicyFileDigests(r.arg, r.reply)
	if r.done != nil {
		r.done <- err
	}
}

func (f *FsScannerRpc) TracingPolicyFileDigests(args *fm.FsScannerDigests, reply *map[string]string) error {
	r := rpcDigests{
		arg:   args,
		reply: reply,
		done:  make(chan error),
	}

	select {
	case runnerChan <- r:
		select { // wait for operation to complete
		case err := <-r.done:
			return err
		case <-time.After(10 * time.Minute):
			return fmt.Errorf("op TracingPolicyFileDigests timed out")
		}
	default:
		return fmt.Errorf("runnerChan is full")
	}
}

type rpcContainerDigests struct {
	arg   *fm.FsScannerContainerDigests
	reply *map[string]string
	done  chan error
}

func (r rpcContainerDigests) Run() {
	err := tracingPolicyContainerFileDigests(r.arg, r.reply)
	if r.done != nil {
		r.done <- err
	}
}

func (f *FsScannerRpc) TracingPolicyContainerFileDigests(args *fm.FsScannerContainerDigests, reply *map[string]string) error {
	r := rpcContainerDigests{
		arg:   args,
		reply: reply,
		done:  make(chan error),
	}

	select {
	case runnerChan <- r:
		select { // wait for operation to complete
		case err := <-r.done:
			return err
		case <-time.After(10 * time.Minute):
			return fmt.Errorf("op TracingPolicyContainerFileDigests timed out")
		}
	default:
		return fmt.Errorf("runnerChan is full")
	}
}

type rpcInit struct {
	arg   *fm.FsScannerInit
	reply *map[fileapi.InodeKey]fileapi.InodeVal
	done  chan error
}

func (r rpcInit) Run() {
	err := tracingPolicyInit(r.arg, r.reply)
	if r.done != nil {
		r.done <- err
	}
}

func (f *FsScannerRpc) TracingPolicyInit(args *fm.FsScannerInit, reply *map[fileapi.InodeKey]fileapi.InodeVal) error {
	r := rpcInit{
		arg:   args,
		reply: reply,
		done:  make(chan error),
	}

	if args.AddToMaps {
		r.reply = nil
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
	arg   *fm.FsScannerRename
	reply *fm.FsScannerRenameReply
	done  chan error
}

func (r rpcRename) Run() {
	err := renameDir(r.arg, r.reply)
	if r.done != nil {
		r.done <- err
	}
}

func (f *FsScannerRpc) RenameDir(args *fm.FsScannerRename, reply *fm.FsScannerRenameReply) error {
	r := rpcRename{
		arg:   args,
		reply: reply,
		done:  make(chan error),
	}

	select {
	case runnerChan <- r:
		select { // wait for operation to complete
		case err := <-r.done:
			return err
		case <-time.After(10 * time.Minute):
			return fmt.Errorf("op RenameDir timed out")
		}
	default:
		return fmt.Errorf("runnerChan is full")
	}
}

type rpcContainerInit struct {
	arg   *fm.FsScannerContainerInit
	reply *map[fileapi.InodeKey]fileapi.InodeVal
	done  chan error
}

func (r rpcContainerInit) Run() {
	err := tracingPolicyContainerInit(r.arg, r.reply)
	if r.done != nil {
		r.done <- err
	}
}

func (f *FsScannerRpc) TracingPolicyContainerInit(args *fm.FsScannerContainerInit, reply *map[fileapi.InodeKey]fileapi.InodeVal) error {
	r := rpcContainerInit{
		arg:   args,
		reply: reply,
		done:  make(chan error),
	}

	if args.AddToMaps {
		r.reply = nil
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

func tracingPolicyInit(args *fm.FsScannerInit, reply *map[fileapi.InodeKey]fileapi.InodeVal) error {
	var maps fm.InodeStore
	if reply == nil {
		var err error
		var cleanup func()
		maps, cleanup, err = fm.OpenFIMMaps(args.MapDir, args.PolicyName)
		if err != nil {
			return err
		}
		defer cleanup()
	} else {
		maps = fm.InitFimHashMap(*reply)
	}

	logger.GetLogger().Debug("fim: Adding host files")

	locFn := func(v *fileapi.InodeVal) {
		v.LocationFlags = fileapi.HOST_FILE
	}

	for i, p := range args.Spec.PathsPatterns {
		matcher, err := fm.GetMatcher(p)
		if err != nil {
			return err
		}

		if fNum, dNum, err := fm.WalkPathRaw(matcher, uint32(i), maps, fm.AddToMap, fm.FilterMatch, locFn); err != nil {
			logger.GetLogger().WithField("path", fm.PathPatternToString(p)).WithField("tracing-policy", args.PolicyName).WithError(err).Warnf("Adding host files/directories failed")
		} else {
			logger.GetLogger().WithField("path", fm.PathPatternToString(p)).WithField("tracing-policy", args.PolicyName).WithField("num-files", fNum).WithField("num-dirs", dNum).Debug("Added host files/directories")
		}
	}

	for _, p := range args.Spec.PathsExclude {
		matcher := fm.PrefixPathMatcher{
			Prefix: p,
		}
		if fNum, dNum, err := fm.WalkPathRaw(matcher, 0, maps, fm.RemoveFromMap, fm.FilterIgnore, locFn); err != nil {
			logger.GetLogger().WithField("path", p).WithField("tracing-policy", args.PolicyName).WithError(err).Warnf("Excluding host files/directories failed")
		} else {
			logger.GetLogger().WithField("path", p).WithField("tracing-policy", args.PolicyName).WithField("num-files", fNum).WithField("num-dirs", dNum).Debug("Excluded host files/directories")
		}
	}

	return nil
}

type readerCtx struct {
	ctx context.Context
	r   io.Reader
}

func (rc readerCtx) Read(p []byte) (n int, err error) {
	if err := rc.ctx.Err(); err != nil {
		return 0, err
	}
	return rc.r.Read(p)
}

func newReaderCtx(ctx context.Context, rdr io.Reader) io.Reader {
	return &readerCtx{
		ctx: ctx,
		r:   rdr,
	}
}

func tracingPolicyFileDigests(args *fm.FsScannerDigests, reply *map[string]string) error {
	h, err := fm.GetHashAlgo(args.Algo)
	if err != nil {
		return fmt.Errorf("tracingPolicyFileDigests: fm.GetHashAlgo: %w", err)
	}

	for _, path := range args.Files {
		f, err := os.Open(path)
		if err != nil {
			// file does not exist, skip that
			continue
		}
		defer f.Close()

		stat, err := f.Stat()
		if err != nil {
			return fmt.Errorf("tracingPolicyFileDigests: f.Stat: %w", err)
		}

		// we cannot get digests for non-regular files
		if !stat.Mode().IsRegular() {
			logger.GetLogger().WithField("path", path).WithField("mode", stat.Mode()).Warn("Skipping non-regular files for digest computation")
			continue
		}

		if stat.Size() > maxFileSizeDigest {
			logger.GetLogger().WithField("file-size", stat.Size()).WithField("max-file-size", maxFileSizeDigest).WithField("path", path).Warn("Skipping file for digest computation due to large size")
			continue
		}

		// we should not spend more than 30 seconds to generate a digest of a file
		// this means that the file is very large so return an error in that case
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(maxTimeoutDigestSeconds)*time.Second)
		defer cancel()

		if _, err := io.Copy(h, newReaderCtx(ctx, f)); err != nil {
			return fmt.Errorf("tracingPolicyFileDigests: io.Copy: %w", err)
		}
		digest := fmt.Sprintf("%x", h.Sum(nil))

		(*reply)[path] = digest
	}

	return nil
}

func tracingPolicyContainerFileDigests(args *fm.FsScannerContainerDigests, reply *map[string]string) error {
	h, err := fm.GetHashAlgo(args.Algo)
	if err != nil {
		return err
	}

	for _, tp := range args.Tp {
		// check if we care about this namespace
		if !fm.MatchPodSelector(tp.Spec.PodSelector, args.PodNs, args.PodName) {
			continue
		}

		logger.GetLogger().WithField("ns", args.PodNs).WithField("app", args.PodName).WithField("cid", args.ContainerID).Debug("fim: Adding digests for files")

		rootDir := args.RootDir
		if rootDir == "" {
			rootDir, err = fm.ContainerIdToRootFs(args.ContainerID, containerRuntimeEndpoint)
			if err != nil {
				return fmt.Errorf("failed to resolve container rootDir: %w", err)
			}
		}

		var handle *ebpf.Map
		if args.AddToMaps {
			handle, err = ebpf.LoadPinnedMap(program.PolicyMapPath(args.MapDir, tp.PolicyName, fm.FilenameDigestMapName), nil)
			if err != nil {
				return err
			}
			defer handle.Close()
		}

		walkFn := func() error {
			for _, path := range tp.DigestPaths {
				f, err := os.Open(path)
				if err != nil {
					continue // file does not exist, skip that
				}
				defer f.Close()

				stat, err := f.Stat()
				if err != nil {
					return fmt.Errorf("tracingPolicyContainerFileDigests: f.Stat: %w", err)
				}

				// we cannot get digests for non-regular files
				if !stat.Mode().IsRegular() {
					logger.GetLogger().WithField("path", path).WithField("mode", stat.Mode()).Warn("Skipping non-regular files for digest computation")
					continue
				}

				if stat.Size() > maxFileSizeDigest {
					logger.GetLogger().WithField("file-size", stat.Size()).WithField("max-file-size", maxFileSizeDigest).WithField("path", path).Warn("Skipping file for digest computation due to large size")
					continue
				}

				// we should not spend more than 30 seconds to generate a digest of a file
				// this means that the file is very large so return an error in that case
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(maxTimeoutDigestSeconds)*time.Second)
				defer cancel()

				if _, err := io.Copy(h, newReaderCtx(ctx, f)); err != nil {
					return fmt.Errorf("tracingPolicyContainerFileDigests: io.Copy: %w", err)
				}
				digest := fmt.Sprintf("%x", h.Sum(nil))

				if args.AddToMaps {
					meta, ok := tp.PathMetadata[path]
					if !ok {
						continue // nothing needs to be set here
					}

					for _, m := range meta {
						var innerMapID ebpf.MapID
						if err := handle.Lookup(m.SelIdx, &innerMapID); err != nil {
							continue
						}

						var innerMap *ebpf.Map
						if innerMap, err = ebpf.NewMapFromID(innerMapID); err != nil {
							return fmt.Errorf("tracingPolicyContainerFileDigests: ebpf.NewMapFromID: %w", err)
						}

						if err := innerMap.Put(fm.CreateDigestKey(digest, args.Algo), m.PathIdx); err != nil {
							return fmt.Errorf("tracingPolicyContainerFileDigests: innerMap.Put: %w", err)
						}
					}
				} else {
					(*reply)[path] = digest
				}
			}
			return nil
		}

		// enter chroot
		exit, err := chroot(rootDir)
		if err != nil {
			return fmt.Errorf("chroot to %s: %w", rootDir, err)
		}

		walkErr := walkFn()

		// exit from the chroot
		if err := exit(); err != nil {
			return fmt.Errorf("exit from chroot: %w", err)
		}

		if walkErr != nil {
			return walkErr
		}
	}

	return nil
}

func renameDir(args *fm.FsScannerRename, reply *fm.FsScannerRenameReply) error {
	maps, cleanup, err := fm.OpenFIMMaps(args.MapDir, args.PolicyName)
	if err != nil {
		return err
	}
	defer cleanup()

	// this should always be prefix-free
	containerID := fm.RemoveContainerIdPrefix(args.ContainerID)

	locFn := func(v *fileapi.InodeVal) {
		if containerID == "" {
			v.LocationFlags = fileapi.HOST_FILE
		} else {
			var cid [64]byte
			copy(cid[:], containerID)
			v.ContainerID = cid
			v.LocationFlags = fileapi.CONTAINER_FILE
		}
	}

	actionFn := func(path string, mode fs.FileMode) (uint32, uint32, error) {
		return fm.CheckPath(args.Spec, path, mode)
	}

	hasFlag := func(flags, flag uint32) bool {
		return (flags & flag) != 0
	}

	if hasFlag(args.Flags, fm.MOVE_OUTSIDE) || hasFlag(args.Flags, fm.MOVE_INTERNALLY) {
		if num, err := fm.WalkPathRenameCleanup(args.WalkPath, maps); err != nil {
			logger.GetLogger().WithField("path", args.WalkPath).WithField("tracing-policy", args.PolicyName).WithError(err).Warnf("Removing files/directories during rename failed")
		} else {
			reply.Diff -= num
		}
	}

	if hasFlag(args.Flags, fm.MOVE_INSIDE) || hasFlag(args.Flags, fm.MOVE_INTERNALLY) {
		if num, err := fm.WalkPathRenameAdd(args.WalkPath, maps, actionFn, locFn); err != nil {
			logger.GetLogger().WithField("path", args.WalkPath).WithField("tracing-policy", args.PolicyName).WithError(err).Warnf("Adding files/directories during rename failed")
		} else {
			reply.Diff += num
		}
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

func tracingPolicyContainerInit(args *fm.FsScannerContainerInit, reply *map[fileapi.InodeKey]fileapi.InodeVal) error {
	for _, tp := range args.Tp {
		// check if we care about this namespace
		if !fm.MatchPodSelector(tp.Spec.PodSelector, args.PodNs, args.PodName) {
			continue
		}

		logger.GetLogger().WithField("ns", args.PodNs).WithField("app", args.PodName).WithField("cid", args.ContainerID).Debug("fim: Adding container files")

		var maps fm.InodeStore
		var err error
		if reply == nil {
			var cleanup func()
			maps, cleanup, err = fm.OpenFIMMaps(args.MapDir, tp.PolicyName)
			if err != nil {
				return fmt.Errorf("OpenFIMMaps(%s, %s): %w", args.MapDir, tp.PinPath, err)
			}
			defer cleanup()
		} else {
			maps = fm.InitFimHashMap(*reply)
		}

		rootDir := args.RootDir
		if rootDir == "" {
			rootDir, err = fm.ContainerIdToRootFs(args.ContainerID, containerRuntimeEndpoint)
			if err != nil {
				return fmt.Errorf("failed to resolve container rootDir: %w", err)
			}
		}
		containerID := fm.RemoveContainerIdPrefix(args.ContainerID)

		locFn := func(v *fileapi.InodeVal) {
			v.LocationFlags = fileapi.CONTAINER_FILE
			copy(v.ContainerID[:], []byte(containerID))
		}

		walkFn := func() error {
			for i, p := range tp.Spec.PathsPatterns {
				matcher, err := fm.GetMatcher(p)
				if err != nil {
					return err
				}

				if fNum, dNum, err := fm.WalkPathRaw(matcher, uint32(i), maps, fm.AddToMap, fm.FilterMatch, locFn); err != nil {
					logger.GetLogger().WithField("path", fm.PathPatternToString(p)).WithField("tracing-policy", tp.Spec).WithField("containerID", containerID).WithError(err).Warnf("Adding container files/directories failed")
				} else {
					logger.GetLogger().WithField("path", fm.PathPatternToString(p)).WithField("tracing-policy", tp.Spec).WithField("containerID", containerID).WithField("num-files", fNum).WithField("num-dirs", dNum).Debug("Added container files/directories")
				}
			}

			for _, p := range tp.Spec.PathsExclude {
				matcher := fm.PrefixPathMatcher{
					Prefix: p,
				}
				if fNum, dNum, err := fm.WalkPathRaw(matcher, 0, maps, fm.RemoveFromMap, fm.FilterIgnore, locFn); err != nil {
					logger.GetLogger().WithField("path", p).WithField("tracing-policy", tp.Spec).WithField("containerID", containerID).WithError(err).Warnf("Excluding container files/directories failed")
				} else {
					logger.GetLogger().WithField("path", p).WithField("tracing-policy", tp.Spec).WithField("containerID", containerID).WithField("num-files", fNum).WithField("num-dirs", dNum).Debug("Excluded container files/directories")
				}
			}

			return nil
		}

		// enter chroot and run
		exit, err := chroot(rootDir)
		if err != nil {
			return fmt.Errorf("chroot to %s: %w", rootDir, err)
		}

		walkErr := walkFn()

		// exit from the chroot
		if err := exit(); err != nil {
			return fmt.Errorf("exit from chroot: %w", err)
		}

		if walkErr != nil {
			return walkErr
		}
	}
	return nil
}

func tracingPolicyContainerDestroy(args *fm.FsScannerContainerDestroy) error {
	containerID := fm.RemoveContainerIdPrefix(args.ContainerID)
	for _, tp := range args.Tp {
		handle, err := ebpf.LoadPinnedMap(program.PolicyMapPath(args.MapDir, tp.PolicyName, fm.InodeMapName), nil)
		if err != nil {
			return err
		}
		defer handle.Close()

		if err := fm.RemoveContainerEntries(handle, containerID); err != nil {
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
	flag.Int64Var(&maxFileSizeDigest, "maxSizeFileDigest", 1*1024*1024*1024, "Set the maximum file size that we will compute a digest (in bytes)")
	flag.Int64Var(&maxTimeoutDigestSeconds, "maxTimeoutFileDigest", 30, "Set the timeout when computing a file digest (in seconds)")
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
		logger.GetLogger().Warnf("hostMntNs flag is not passed in tetragon-fs-scanner")
		os.Exit(1)
	}

	if !isFlagPassed("scannerFifoPath") {
		logger.GetLogger().Warnf("scannerFifoPath flag is not passed in tetragon-fs-scanner")
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
		logger.GetLogger().Warnf("Mnt namespace of tetragon-fs-scanner (%d) does not match host mnt namespace", inum)
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
