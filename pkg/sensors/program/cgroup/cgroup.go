// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !windows

package cgroup

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/sensors/unloader"
	"golang.org/x/sys/unix"
)

const (
	fgsCgroupPath = "/run/tetragon/cgroup2"
)

func LoadSockOpt(
	bpfDir string,
	load *program.Program,
	maps []*program.Map,
	verbose int,
) error {
	return LoadCgroupProgram(bpfDir, load, maps, verbose)
}

func LoadCgroupProgram(
	bpfDir string,
	load *program.Program, maps []*program.Map, verbose int) error {
	// Previously, we cached the cgroup path open file descriptor and reused it.
	// In testing, multiple starts/stops of Tetragon appear to sometimes invalidate
	// the cached value, leading to failure.
	// Instead, we will open the path each time (and will close it to save file
	// descriptors) as we only do this when we load a CGroup program and that
	// doesn't happen often enough for the caching to be beneficial over the risk
	// of failing to negate the cached value at the correct points during close
	// down.
	// We also add the O_CLOEXEC flag to prevent this file descriptor dangling in
	// a forked child.
	fgsCgroupFD, err := unix.Open(fgsCgroupPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("failed to open '%s': %w", fgsCgroupPath, err)
	}
	defer unix.Close(fgsCgroupFD)
	return program.LoadProgram(bpfDir, load, maps, CGroupAttachWithFlags(fgsCgroupFD, unix.BPF_F_ALLOW_MULTI), verbose)
}

// New attach function that uses a new unloader. The new unloader opens the
// CGroup file itself rather than relying on a passed in file descriptor.
// This should probably be ported to OSS but a) we need it now for Hypershield
// (the related bug is holding up CI); and b) OSS doesn't use CGroup or
// SockOps yet.
func CGroupAttachWithFlags(targetFD int, flags uint32) program.AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		err := link.RawAttachProgram(link.RawAttachProgramOptions{
			Target:  targetFD,
			Program: prog,
			Attach:  spec.AttachType,
			Flags:   flags,
		})
		if err != nil {
			prog.Close()
			return nil, fmt.Errorf("attaching '%s' failed: %w", spec.Name, err)
		}
		return unloader.ChainUnloader{
			unloader.ProgUnloader{
				Prog: prog,
			},
			&CGroupDetachUnloader{
				Name:       spec.Name,
				Prog:       prog,
				AttachType: spec.AttachType,
			},
		}, nil
	}
}

// cgroupDetachUnloader can be used to unload cgroup and sockmap programs.
type CGroupDetachUnloader struct {
	Name       string
	Prog       *ebpf.Program
	AttachType ebpf.AttachType
}

func (rdu *CGroupDetachUnloader) Unload(unpin bool) error {
	defer rdu.Prog.Close()
	// PROG_ATTACH does not return any link, so there's nothing to unpin,
	// but we must skip the detach operation for 'unpin == false' otherwise
	// the pinned program will be un-attached
	if unpin {
		fgsCgroupFD, err := unix.Open(fgsCgroupPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("failed to open '%s': %w", fgsCgroupPath, err)
		}
		defer unix.Close(fgsCgroupFD)

		err = link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  fgsCgroupFD,
			Program: rdu.Prog,
			Attach:  rdu.AttachType,
		})
		if err != nil {
			return fmt.Errorf("failed to detach %s: %w", rdu.Name, err)
		}
	}
	return nil
}

func DetachTetragonCgroups(tgTypes, bestEffort bool) error {
	httpSockfd := int(0)
	tlsSockfd := int(0)
	nopSockfd := int(0)

	cgrpfd, err := unix.Open(fgsCgroupPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("failed to open '%s': %w", fgsCgroupPath, err)
	}
	defer unix.Close(cgrpfd)

	// walk maps to find sockmap so we can detach skmsg skskb and nop
	mapID := ebpf.MapID(0)
	for {
		mapID, err = ebpf.MapGetNextID(mapID)
		if err != nil {
			break
		}
		m, err := ebpf.NewMapFromID(mapID)
		if err != nil {
			break
		}
		defer m.Close()
		if m.Type() == ebpf.SockHash {
			n := m.String()
			if strings.Contains(n, "http_sock_map") {
				httpSockfd = m.FD()
			}
			if strings.Contains(n, "tls_sock_map") {
				tlsSockfd = m.FD()
			}
			if strings.Contains(n, "nop_sock_map") {
				nopSockfd = m.FD()
			}
		}
	}

	// Finds a specific map associated with the program protocol type
	findSockFD := func(n string) int {
		fd := int(0)
		if strings.Contains(n, "http") {
			fd = httpSockfd
		} else if strings.Contains(n, "tls") {
			fd = tlsSockfd
		} else if strings.Contains(n, "nop") {
			fd = nopSockfd
		} else {
			logger.GetLogger().Warn("Discovered SkMsg program with unknown name", "mapName", n)
		}
		return fd
	}

	progID := ebpf.ProgramID(0)
	for {
		progID, err = ebpf.ProgramGetNextID(progID)
		if err != nil {
			break
		}

		prog, err := ebpf.NewProgramFromID(progID)
		if err != nil {
			continue
		}
		defer prog.Close()

		n := prog.String()
		// For now do the dumb thing and just attempt to detach from
		// things we know we could be attached to. With some guardrails
		// to only work on programs with names  we recognize.
		// Don't report errors if RawDetachProgram returns "no such file or directory",
		// as that simply means we've already detached it correctly.
		switch prog.Type() {
		case ebpf.CGroupSKB:
			if bestEffort {
				if !strings.Contains(n, "inet_send") &&
					!strings.Contains(n, "inet_recv") &&
					!strings.Contains(n, "inet_lazy_recv") &&
					!strings.Contains(n, "inet_lazy_send") &&
					!strings.Contains(n, "tls_inet_send") &&
					!strings.Contains(n, "tls_inet_recv") &&
					!strings.HasPrefix(n, "tg_") &&
					!strings.HasPrefix(n, "CGroupSKB(tg_") {
					break
				}
			} else if tgTypes {
				if !strings.HasPrefix(n, "tg_") &&
					!strings.HasPrefix(n, "CGroupSKB(tls_inet_") &&
					!strings.HasPrefix(n, "CGroupSKB(tg_") {
					break
				}
			} else {
				break
			}
			opts := link.RawDetachProgramOptions{
				Target:  cgrpfd,
				Program: prog,
			}
			opts.Attach = ebpf.AttachCGroupInetIngress
			if err := link.RawDetachProgram(opts); err != nil {
				opts.Attach = ebpf.AttachCGroupInetEgress
				if err := link.RawDetachProgram(opts); err != nil && !errors.Is(err, fs.ErrNotExist) {
					logger.GetLogger().Warn("RawDetachProgram CgroupSKB error", logfields.Error, err,
						"Target", cgrpfd, "Program", prog)
				}
			}
		case ebpf.SkMsg:
			if bestEffort {
				if !strings.Contains(n, "http_skmsg") &&
					!strings.Contains(n, "http_sk_msg") &&
					!strings.Contains(n, "fgs") &&
					!strings.Contains(n, "tls_skmsg") &&
					!strings.Contains(n, "tls_sk_msg") &&
					!strings.Contains(n, "nop_skmsg") &&
					!strings.HasPrefix(n, "tg_") &&
					!strings.HasPrefix(n, "SkMsg(tg_") {
					break
				}
			} else if tgTypes {
				if !strings.HasPrefix(n, "tg_") &&
					!strings.HasPrefix(n, "SkMsg(tg_") {
					break
				}
			} else {
				break
			}

			sockfd := findSockFD(n)
			if sockfd == 0 {
				break
			}

			opts := link.RawDetachProgramOptions{
				Target:  sockfd,
				Program: prog,
				Attach:  ebpf.AttachSkMsgVerdict,
			}
			if err := link.RawDetachProgram(opts); err != nil && !errors.Is(err, fs.ErrNotExist) {
				logger.GetLogger().Warn("RawDetachProgram SkMsg error", logfields.Error, err)
			}
		case ebpf.SkSKB:
			if bestEffort {
				if !strings.Contains(n, "bpf_http_parser") &&
					!strings.Contains(n, "bpf_http_verdict") &&
					!strings.Contains(n, "bpf_skskb_http_verdict") &&
					!strings.Contains(n, "bpf_tls_skskb") &&
					!strings.Contains(n, "bpf_nop_") &&
					!strings.HasPrefix(n, "tg_") &&
					!strings.HasPrefix(n, "SkSKB(tg_") {
					break
				}
			} else if tgTypes {
				if !strings.HasPrefix(n, "tg_") &&
					!strings.HasPrefix(n, "SkSKB(tg_") {
					break
				}
			} else {
				break
			}

			sockfd := findSockFD(n)
			if sockfd == 0 {
				break
			}

			opts := link.RawDetachProgramOptions{
				Target:  sockfd,
				Program: prog,
				Attach:  ebpf.AttachSkSKBStreamVerdict,
			}
			// These errors are debug only because we are expect an error here we don't
			// know the type so we just guess and try to remove all of them.
			if err := link.RawDetachProgram(opts); err != nil {
				logger.GetLogger().Debug("RawDetachProgram AttachSkSKBStreamVerdict error", logfields.Error, err)
			}
			opts.Attach = ebpf.AttachSkSKBStreamParser
			if err := link.RawDetachProgram(opts); err != nil {
				logger.GetLogger().Debug("RawDetachProgram AttachSkSKBStreamParser error", logfields.Error, err)
			}
			opts.Attach = ebpf.AttachSkSKBVerdict
			if err := link.RawDetachProgram(opts); err != nil {
				logger.GetLogger().Debug("RawDetachProgram AttachSkSKBVerdict error", logfields.Error, err)
			}
		case ebpf.SockOps:
			if bestEffort {
				if !strings.Contains(n, "fgs") &&
					!strings.Contains(n, "bpf_sockmap") &&
					!strings.HasPrefix(n, "tg_") &&
					!strings.HasPrefix(n, "SockOps(tg_") {
					break
				}
			} else if tgTypes {
				if !strings.HasPrefix(n, "tg_") &&
					!strings.HasPrefix(n, "SockOps(tg_") {
					break
				}
			} else {
				break
			}
			opts := link.RawDetachProgramOptions{
				Target:  cgrpfd,
				Program: prog,
				Attach:  ebpf.AttachCGroupSockOps,
			}
			if err := link.RawDetachProgram(opts); err != nil && !errors.Is(err, fs.ErrNotExist) {
				logger.GetLogger().Warn("RawDetachProgram SockOps error", logfields.Error, err)
			}
		case ebpf.CGroupSockopt:
			if bestEffort {
				if !strings.Contains(n, "fgs") &&
					!strings.Contains(n, "setsockopt") &&
					!strings.HasPrefix(n, "tg_") &&
					!strings.HasPrefix(n, "CGroupSockopt(tg_") {
					break
				}
			} else if tgTypes {
				if !strings.HasPrefix(n, "tg_") &&
					!strings.HasPrefix(n, "CGroupSockopt(tg_") {
					break
				}
			}
			opts := link.RawDetachProgramOptions{
				Target:  cgrpfd,
				Program: prog,
				Attach:  ebpf.AttachCGroupSetsockopt,
			}
			if err := link.RawDetachProgram(opts); err != nil && !errors.Is(err, fs.ErrNotExist) {
				logger.GetLogger().Warn("RawDetachProgram Sockopt error", logfields.Error, err)
			}
		case ebpf.CGroupSock:
			if bestEffort {
				if !strings.Contains(n, "fgs") &&
					!strings.Contains(n, "tg_udp_bind_dummy") &&
					!strings.HasPrefix(n, "tg_") &&
					!strings.HasPrefix(n, "CGroupSock(tg_") {
					break
				}
			} else if tgTypes {
				if !strings.HasPrefix(n, "tg_") &&
					!strings.HasPrefix(n, "CGroupSock(tg_") {
					break
				}
			}
			opts := link.RawDetachProgramOptions{
				Target:  cgrpfd,
				Program: prog,
				Attach:  ebpf.AttachCGroupInet4PostBind,
			}
			if err := link.RawDetachProgram(opts); err != nil {
				opts.Attach = ebpf.AttachCGroupInet6PostBind
				if err := link.RawDetachProgram(opts); err != nil && !errors.Is(err, fs.ErrNotExist) {
					logger.GetLogger().Warn("RawDetachProgram CgroupSock error", logfields.Error, err)
				}
			}
		}
	}
	return nil
}
