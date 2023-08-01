package ip

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/yalue/native_endian"

	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	"github.com/isovalent/hubble-fgs/pkg/metrics/iperrormetrics"
	"github.com/isovalent/hubble-fgs/pkg/sensors/stats"
)

var (
	enableDns = false
)

func EnableDns() {
	enableDns = true
}

func DisableDns() {
	enableDns = false
}

func MsgToIPUnix(m *api.MsgIPEvent, rtt bool, udpLatency bool) *layer3.MsgIPEventUnix {
	unix := &layer3.MsgIPEventUnix{}

	unix.Common = m.Common
	unix.Tuple = m.Tuple
	unix.Return = m.Return
	unix.ProcessKey = m.ProcessKey
	unix.SockCookie = m.SockCookie
	unix.SocketStats = stats.MsgToSocketStatsUnix(&m.SocketStats, rtt, udpLatency)
	unix.SocketFlags = m.SocketFlags
	unix.Duration = time.Duration(m.Duration * uint64(time.Nanosecond))
	unix.Data = m.Duration // For IP_ERROR messages
	// no need to copy the pad here
	if enableDns {
		unix.SocketFlags |= api.SOCKFLAGS_TYPE_DNSREADY
	}

	return unix
}

func getNetNs(nsPath string) (uint64, error) {
	inodeStr, err := os.Readlink(nsPath)
	if err != nil {
		return 0, err
	}
	if !strings.HasPrefix(inodeStr, "net:[") {
		return 0, fmt.Errorf("incorrect prefix")
	}
	inode, err := strconv.ParseUint(inodeStr[5:len(inodeStr)-1], 10, 64)
	if err != nil {
		return 0, err
	}
	return inode, nil
}

func getInodeForCookieFromFile(cookie uint64, netFile string) (uint64, error) {
	fileBytes, err := os.ReadFile(netFile)
	if err != nil {
		return 0, err
	}
	fileString := string(fileBytes)
	fileLines := strings.Split(fileString, "\n")[1:]
	for _, line := range fileLines {
		entries := strings.Fields(line)
		if len(entries) < 12 {
			return 0, fmt.Errorf("file does not include cookie column")
		}
		entryCookie, err := strconv.ParseUint(entries[11], 16, 64)
		if err != nil {
			return 0, fmt.Errorf("cannot parse cookie")
		}
		if cookie != entryCookie {
			continue
		}
		inode, err := strconv.ParseUint(entries[9], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("cannot parse inode")
		}
		return inode, nil
	}
	return 0, fmt.Errorf("inode not found")
}

func getInodeForCookie(cookie uint64, netPath string) (uint64, bool, error) {
	for _, file := range [...]string{"tcp", "tcp6", "udp", "udp6"} {
		inode, err := getInodeForCookieFromFile(cookie, filepath.Join(netPath, file))
		if err != nil {
			return inode, file[len(file)-1] == '6', nil
		}
	}
	return 0, false, fmt.Errorf("inode not found")
}

func getFdForInode(inode uint64, fdPath string) (int, error) {
	fdDir, err := os.ReadDir(fdPath)
	if err != nil {
		return 0, err
	}

	for _, fd := range fdDir {
		fdLink, err := os.Readlink(filepath.Join(fdPath, fd.Name()))
		if err != nil {
			continue
		}
		fdInode := uint64(0)
		if strings.HasPrefix(fdLink, "socket:[") {
			fdInode, err = strconv.ParseUint(fdLink[8:len(fdLink)-1], 10, 64)
			if err != nil {
				continue
			}
		} else if strings.HasPrefix(fdLink, "[0000]:") {
			fdInode, err = strconv.ParseUint(fdLink[7:], 10, 64)
			if err != nil {
				continue
			}
		}
		if fdInode == inode {
			fdNum, err := strconv.ParseInt(fd.Name(), 10, 32)
			if err != nil {
				return 0, err
			}
			return int(fdNum), nil
		}
	}
	return 0, fmt.Errorf("failed to find fd for inode")
}

func findPidFdForCookie(cookie uint64) (int, int, int, error) {
	wrongNs := make(map[uint64]bool)
	foundInode := uint64(0)
	foundNs := uint64(0)
	foundFamily := int(0)

	procFS, err := os.ReadDir(option.Config.ProcFS)
	if err != nil {
		logger.GetLogger().WithError(err).Errorf("Could not read directory %s", option.Config.ProcFS)
		return 0, 0, 0, err
	}

	for _, d := range procFS {
		if !d.IsDir() {
			continue
		}

		pathName := filepath.Join(option.Config.ProcFS, d.Name())

		// Ignore any non-process directories
		cmdline, err := os.ReadFile(filepath.Join(pathName, "cmdline"))
		if err != nil {
			continue
		}
		if string(cmdline) == "" {
			continue
		}

		// Get the net namespace for the process
		netNs, err := getNetNs(filepath.Join(pathName, "ns", "net"))
		if err != nil {
			return 0, 0, 0, err
		}

		// If we haven't yet identified the inode, look it up and store it, or log the
		// namespace as wrong and go to the next process.
		if foundInode == 0 {
			// wrongNs is a set of namespaces that don't contain our PID.
			_, ok := wrongNs[netNs]
			if ok {
				continue
			}

			inode, ipv6, err := getInodeForCookie(cookie, filepath.Join(pathName, "net"))
			if err != nil {
				wrongNs[netNs] = true
				continue
			}

			foundInode = inode
			foundNs = netNs
			if ipv6 {
				foundFamily = syscall.AF_INET6
			} else {
				foundFamily = syscall.AF_INET
			}
		}

		// Check if this process is in the correct network namespace
		if netNs != foundNs {
			continue
		}

		// Check if this process has an FD for the found inode.
		fd, err := getFdForInode(foundInode, filepath.Join(pathName, "fd"))
		if err == nil {
			pid, err := strconv.ParseInt(d.Name(), 10, 32)
			if err != nil {
				return 0, 0, 0, err
			}
			return int(pid), fd, foundFamily, nil
		}
	}
	return 0, 0, 0, fmt.Errorf("failed to find pid and fd for cookie")
}

func HandleIpError(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgIPEvent{}
	err := binary.Read(r, native_endian.NativeEndian(), &m)
	if err != nil {
		return nil, err
	}

	if m.Return >= 0 && m.Return <= layer3.IpErrorMax && layer3.IpErrorToString[m.Return] == "UDP stack burst no process" {
		pid, fd, family, err := findPidFdForCookie(m.SockCookie)
		if err == nil {
			GetSocketForFD(syscall.IPPROTO_UDP, pid, fd, m.SockCookie, family)
		}
	}

	if m.Return >= 0 && m.Return <= layer3.IpErrorMax &&
		(layer3.IpErrorToString[m.Return] == "UDP stack burst no process" ||
			layer3.IpErrorToString[m.Return] == "Socket discovery read error") {
		// Just increment the metric and don't report the event.
		var version string
		if m.Tuple.IPv6 == 0 {
			version = "IPv4"
		} else {
			version = "IPv6"
		}
		iperrormetrics.ProcessIpErrors(layer3.IpErrorToString[m.Return], version).Inc()
		return nil, fmt.Errorf("IP Error handled as metric only")
	}

	msgUnix := MsgToIPUnix(&m, false, false)
	return []observer.Event{msgUnix}, nil
}
