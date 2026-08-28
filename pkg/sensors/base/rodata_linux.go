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

package base

import (
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/program"

	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

var (
	// RodataConfigMap is hubble-fgs's own instance of OSS's shared rodata_config map.
	RodataConfigMap = base.MapBuilderRodataConfigAtInit(
		ExecveV511, ExecveV61, ExecveV612)

	FgsRodataConfigMap = program.MapBuilderRodataConfigAtInit(
		".rodata.fgs_config", "fgs_rodata_config",
		func() (any, error) { return fgsRodataCurrent() },
		ExecveV53, ExecveV511, ExecveV61, ExecveV612)
)

// independent frozen rodata config map
// Its BPF-side counterpart is bpf/lib/fgs_rodata_config.h.
type fgsRodataConfig struct {
	DNSParserPerPodEnabled     uint8
	MulticastInspectionEnabled uint8
	CgroupProbeReadEnabled     uint8
	DNSParserEnabled           uint8
	IGMPv3MaxEventFrags        uint16
	IGMPv3MaxPMCs              uint16
	IGMPv3MaxSources           uint16
	BpfDebugEnabled            uint8
	Pad                        [3]uint8
}

func b2u8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func fgsRodataCurrent() (fgsRodataConfig, error) {
	dnsParserPerPodEnabled := b2u8(enterpriseOption.Config.EnableBPFDNSPerPod &&
		utils.SockopsSupportsCgroupAncestorHelper())

	// Only available from 6.12, same condition used today by
	// layer3's own multicast sampling rewrite.
	multicastInspectionEnabled := b2u8(kernels.MinKernelVersion("6.12"))

	cgroupProbeReadEnabled := b2u8(utils.SupportCGroupSKBProbeRead())

	// layer3 only ever rewrote this constant on its process-tree
	// dispatcher variant - the plain dispatcher (no process tree
	// support) always kept DNS parsing off regardless of config.
	// Preserve that gate here since this is now one shared value.
	dnsParserEnabled := b2u8(utils.SupportProcessTree() &&
		enterpriseOption.Config.EnableBPFDNSParser)

	// IGMP group-record loop bound - never varies today, unlike
	// TG_IGMPV3_MAX_PMCS which scales with kernel version.
	igmpV3MaxEventFrags := uint16(16)

	igmpV3MaxPMCs := igmpMaxPMCs()

	// IGMP source-list loop bound - never varies today.
	igmpV3MaxSources := uint16(256)

	// bpf debug match enabled by --bpf-debug for EE specific bpf areas
	bpfDebugEnabled := enterpriseOption.Config.BPFDebugAreas.ToFGSBPFConfig()

	return fgsRodataConfig{
		DNSParserPerPodEnabled:     dnsParserPerPodEnabled,
		MulticastInspectionEnabled: multicastInspectionEnabled,
		CgroupProbeReadEnabled:     cgroupProbeReadEnabled,
		DNSParserEnabled:           dnsParserEnabled,
		IGMPv3MaxEventFrags:        igmpV3MaxEventFrags,
		IGMPv3MaxPMCs:              igmpV3MaxPMCs,
		IGMPv3MaxSources:           igmpV3MaxSources,
		BpfDebugEnabled:            bpfDebugEnabled,
	}, nil
}

func igmpMaxPMCs() uint16 {
	// Further verifier changes after 6.6 but before 6.12 allow more loop
	// iterations - see igmp.go's EnableIgmp() for the matching >=6.6 gate
	// on group-record support itself.
	if kernels.MinKernelVersion("6.12") {
		return 128
	}
	return 64
}
