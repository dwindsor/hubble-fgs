//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package sockops

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/cgroup"
)

var (
	// Needed on both the HTTP and TLS programs.
	SockopsEstablished = program.Builder(
		"bpf_sockops.o",
		"sockops",
		"sockops/fgs_sockops",
		"tg_sockops",
		"sockops")

	TlsSockMapName  = "tg_tls_sock_map"
	httpSockMapName = "tg_http_sock_map"
	NopSockMapName  = "tg_nop_sock_map"

	HttpSockMap   = program.MapBuilder(httpSockMapName, SockopsEstablished)
	TlsSockMap    = program.MapBuilder(TlsSockMapName, SockopsEstablished)
	NopSockMap    = program.MapBuilder(NopSockMapName, SockopsEstablished)
	TlsFilterMap  = program.MapBuilder("tg_tls_filter_map", SockopsEstablished)
	HttpFilterMap = program.MapBuilder("tg_http_filter_map", SockopsEstablished)
	NopFilterMap  = program.MapBuilder("tg_nop_filter_map", SockopsEstablished)
)

const (
	// Needs to be in sync with TLS_MAX_PORTS from tls_map.h
	TLS_MAX_PORTS = 512
)

func init() {
	sockops := &sockopsSensor{
		name: "sockops loader",
	}
	sensors.RegisterProbeType("sockops", sockops)
	sensors.RegisterPolicyHandlerAtInit(sockops.name, sockops)
}

func builder(policy tracingpolicy.TracingPolicy, name string) (sensors.SensorIface, error) {
	var progs []*program.Program
	var maps []*program.Map

	if kernels.MinKernelVersion("5.8.0") {
		logger.GetLogger().Infof("Enable Sockops")
		progs = append(progs, SockopsEstablished)
		maps = append(maps,
			HttpSockMap, TlsSockMap, NopSockMap,
			HttpFilterMap, TlsFilterMap, NopFilterMap, layer3.SocketMap())

		return sensors.SensorBuilder(policy, name, progs, maps), nil
	}
	return nil, nil
}

type sockopsSensor struct {
	name string
}

func (*sockopsSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	err := cgroup.LoadCgroupProgram(args.BPFDir, args.Load, args.Verbose)
	return err
}

func (*sockopsSensor) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	fid policyfilter.PolicyID,
) (sensors.SensorIface, error) {
	parser := policy.TpSpec().Parser
	if (parser.Tls.Enable && parser.Tls.Mode == "socket") ||
		parser.Http.Enable ||
		parser.Nop.Enable {

		if fid != policyfilter.NoFilterID {
			return nil, fmt.Errorf("sockops sensor does not implement policy filtering")
		}

		return builder(policy, "__sockops_sensors__")
	}
	return nil, nil
}

func SetFilter(mapDir string, mapName string, filters []uint32) error {
	selectorMap, err := ebpf.LoadPinnedMap(filepath.Join(mapDir, mapName), nil)
	if err != nil {
		return fmt.Errorf("failed to open selector map '%s': %w", mapName, err)
	}
	defer selectorMap.Close()

	for _, filter := range filters {
		var zero uint8
		/* Some byte hackery here because ports are 16bits in packet, but
		 * we use them as 32bit types (this helps code generation and verifier)
		 * throughout BPF side. But we swap here to avoid doing the swap on data
		 * read from sock/packet.
		 */
		filter = uint32(networkapi.SwapByte(uint16(filter)))
		if err := selectorMap.Update(filter, zero, ebpf.UpdateAny); err != nil {
			return err
		}
	}

	return nil
}
