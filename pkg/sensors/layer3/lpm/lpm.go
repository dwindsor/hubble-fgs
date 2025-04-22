package lpm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
)

type KernelLPMTrie4 struct {
	prefix uint32
	addr   uint32
}

type KernelLPMTrie6 struct {
	prefix uint32
	addr   [16]byte
}

type ValueMap struct {
	Data map[[8]byte]struct{}
}

const (
	addr4lpmMapName = "addr4lpm_map"
	addr6lpmMapName = "addr6lpm_map"
)

type LPMMap struct {
	addr6 *ebpf.Map
	addr4 *ebpf.Map
}

func NewLPM() (*LPMMap, error) {
	fileLpm4 := filepath.Join(bpf.MapPrefixPath(), addr4lpmMapName)
	addr4lpm, err := ebpf.LoadPinnedMap(fileLpm4, nil)
	if err != nil {
		logger.GetLogger().Errorf("failed to pin addr4 LPM Map (%s): %v", fileLpm4, err)
		return nil, err
	}

	fileLpm6 := filepath.Join(bpf.MapPrefixPath(), addr6lpmMapName)
	addr6lpm, err := ebpf.LoadPinnedMap(fileLpm6, nil)
	if err != nil {
		logger.GetLogger().Errorf("failed to pin addr6 LPM Map (%s): %v", fileLpm6, err)
		return nil, err
	}

	return &LPMMap{
		addr6: addr6lpm,
		addr4: addr4lpm,
	}, nil
}

func (lpm *LPMMap) writeIp6(ip string, id uint64) error {
	addr, maskLen, err := parseAddr(ip)
	if err != nil {
		return fmt.Errorf("writeIp6 can not parse %s: %w", ip, err)
	}
	ip4 := binary.LittleEndian.Uint32(addr)
	val := KernelLPMTrie4{prefix: maskLen, addr: ip4}
	if err := lpm.addr4.Update(val, id, 0); err != nil {
		logger.GetLogger().WithError(err).Errorf("Failed to program LPM4 %s->%d", ip, id)
	}
	return nil
}

func (lpm *LPMMap) writeIp4(ip string, id uint64) error {
	addr, maskLen, err := parseAddr(ip)
	if err != nil {
		return fmt.Errorf("writeIp4 can not parse %s: %w", ip, err)
	}
	var addrSlice [16]byte
	copy(addrSlice[:], addr)
	val := KernelLPMTrie6{prefix: maskLen, addr: addrSlice}
	if err := lpm.addr6.Update(val, id, 0); err != nil {
		logger.GetLogger().WithError(err).Errorf("Failed to program LPM6 %s->%d", ip, id)
	}
	return nil
}

func (lpm *LPMMap) Write(ip string, id uint64) error {
	var err error

	ver := net.ParseIP(ip)
	if ver.To4() != nil {
		err = lpm.writeIp4(ip, id)
	} else {
		err = lpm.writeIp6(ip, id)
	}
	return err
}

func parseAddr(v string) ([]byte, uint32, error) {
	ipaddr := net.ParseIP(v)
	if ipaddr != nil {
		ipaddr4 := ipaddr.To4()
		if ipaddr4 != nil {
			return ipaddr4, 32, nil
		}
		ipaddr6 := ipaddr.To16()
		if ipaddr6 != nil {
			return ipaddr6, 128, nil
		}
		return nil, 0, errors.New("IP address is not valid: does not parse as IPv4 or IPv6")
	}
	vParts := strings.Split(v, "/")
	if len(vParts) != 2 {
		return nil, 0, errors.New("IP address is not valid: should be in format ADDR or ADDR/MASKLEN")
	}
	ipaddr = net.ParseIP(vParts[0])
	if ipaddr == nil {
		return nil, 0, errors.New("IP CIDR is not valid: address part does not parse as IPv4 or IPv6")
	}
	maskLen, err := strconv.ParseUint(vParts[1], 10, 32)
	if err != nil {
		return nil, 0, errors.New("IP CIDR is not valid: mask part does not parse")
	}
	ipaddr4 := ipaddr.To4()
	if ipaddr4 != nil {
		if maskLen <= 32 {
			return ipaddr4, uint32(maskLen), nil
		}
		return nil, 0, errors.New("IP CIDR is not valid: IPv4 mask len must be <= 32")
	}
	ipaddr6 := ipaddr.To16()
	if ipaddr6 != nil {
		if maskLen <= 128 {
			return ipaddr6, uint32(maskLen), nil
		}
		return nil, 0, errors.New("IP CIDR is not valid: IPv6 mask len must be <= 128")
	}
	return nil, 0, errors.New("IP CIDR is not valid: address part does not parse")
}
