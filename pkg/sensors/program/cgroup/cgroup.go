package cgroup

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"golang.org/x/sys/unix"
)

const (
	fgsCgroupPath = "/run/tetragon/cgroup2"
)

var (
	fgsCgroupFD = -1
)

func LoadSockOpt(
	bpfDir string,
	load *program.Program,
	verbose int,
) error {
	return LoadCgroupProgram(bpfDir, load, verbose)
}

func LoadCgroupProgram(
	bpfDir string,
	load *program.Program, verbose int) error {
	if fgsCgroupFD < 0 {
		fd, err := unix.Open(fgsCgroupPath, unix.O_RDONLY, 0)
		if err != nil {
			return fmt.Errorf("failed to open '%s': %w", fgsCgroupPath, err)
		}
		fgsCgroupFD = fd
	}
	return program.LoadProgram(bpfDir, load, program.RawAttachWithFlags(fgsCgroupFD, unix.BPF_F_ALLOW_MULTI), verbose)
}

func DetachTetragonCgroups(tgTypes, bestEffort bool) error {
	httpSockfd := int(0)
	tlsSockfd := int(0)
	nopSockfd := int(0)

	cgrpfd, err := unix.Open(fgsCgroupPath, unix.O_RDONLY, 0)
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
			logger.GetLogger().WithField("mapName", n).Warn("Discovered SkMsg program with unknown name")
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
		switch prog.Type() {
		case ebpf.CGroupSKB:
			if bestEffort {
				if !strings.Contains(n, "inet_send") &&
					!strings.Contains(n, "inet_recv") &&
					!strings.Contains(n, "inet_lazy_recv") &&
					!strings.Contains(n, "inet_lazy_send") &&
					!strings.HasPrefix(n, "tg_") &&
					!strings.HasPrefix(n, "CGroupSKB(tg_") {
					break
				}
			} else if tgTypes {
				if !strings.HasPrefix(n, "tg_") &&
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
				if err := link.RawDetachProgram(opts); err != nil {
					logger.GetLogger().WithError(err).Warn("RawDetachProgram CgroupSKB error")
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
			if err := link.RawDetachProgram(opts); err != nil {
				logger.GetLogger().WithError(err).Warn("RawDetachProgram SkMsg error")
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
				logger.GetLogger().WithError(err).Debug("RawDetachProgram AttachSkSKBStreamVerdict error")
			}
			opts.Attach = ebpf.AttachSkSKBStreamParser
			if err := link.RawDetachProgram(opts); err != nil {
				logger.GetLogger().WithError(err).Debug("RawDetachProgram AttachSkSKBStreamParser error")
			}
			opts.Attach = ebpf.AttachSkSKBVerdict
			if err := link.RawDetachProgram(opts); err != nil {
				logger.GetLogger().WithError(err).Debug("RawDetachProgram AttachSkSKBVerdict error")
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
			if err := link.RawDetachProgram(opts); err != nil {
				logger.GetLogger().WithError(err).Warn("RawDetachProgram SockOps error")
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
			if err := link.RawDetachProgram(opts); err != nil {
				logger.GetLogger().WithError(err).Warn("RawDetachProgram Sockopt error")
			}
		case ebpf.CGroupSock:
			logger.GetLogger().WithField("map", n).Warn("CGROUP SOCK")
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
				if err := link.RawDetachProgram(opts); err != nil {
					logger.GetLogger().WithError(err).Warn("RawDetachProgram CgroupSock error")
				}
			}
		}
	}
	return nil
}
