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
	DNSParserPerPodEnabled uint8
	Pad                    [7]uint8
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

	return fgsRodataConfig{
		DNSParserPerPodEnabled: dnsParserPerPodEnabled,
	}, nil
}
