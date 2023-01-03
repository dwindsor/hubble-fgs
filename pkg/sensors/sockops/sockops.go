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
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/cgroup"
	"github.com/isovalent/hubble-fgs/pkg/sensors/tcp"
)

var (
	// Needed on both the HTTP and TLS programs.
	SockopsEstablished = program.Builder(
		"bpf_sockops.o",
		"sockops",
		"sockops/fgs_sockops",
		"sockops_fgs_sockops",
		"sockops")

	TlsSockMapName  = "tls_sock_map"
	httpSockMapName = "http_sock_map"
	NopSockMapName  = "nop_sock_map"

	HttpSockMap   = program.MapBuilder(httpSockMapName, SockopsEstablished)
	TlsSockMap    = program.MapBuilder(TlsSockMapName, SockopsEstablished)
	NopSockMap    = program.MapBuilder(NopSockMapName, SockopsEstablished)
	TlsFilterMap  = program.MapBuilder("tls_filter_map", SockopsEstablished)
	HttpFilterMap = program.MapBuilder("http_filter_map", SockopsEstablished)
	NopFilterMap  = program.MapBuilder("nop_filter_map", SockopsEstablished)
)

func init() {
	sockops := &sockopsSensor{
		name: "sockops loader",
	}
	sensors.RegisterProbeType("sockops", sockops)
	sensors.RegisterSpecHandlerAtInit(sockops.name, sockops)
}

func builder(name string) (*sensors.Sensor, error) {
	var progs []*program.Program
	var maps []*program.Map

	if kernels.MinKernelVersion("5.8.0") {
		logger.GetLogger().Infof("Enable Sockops")
		progs = append(progs, SockopsEstablished)
		maps = append(maps,
			HttpSockMap, TlsSockMap, NopSockMap,
			HttpFilterMap, TlsFilterMap, NopFilterMap, tcp.TlsSocketMap, tcp.SocketMap)

		return sensors.SensorBuilder("__sockops_sensors__", progs, maps), nil
	}
	return nil, nil
}

type sockopsSensor struct {
	name string
}

func (*sockopsSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	err := cgroup.LoadCgroupProgram(args.BPFDir, args.MapDir, args.CiliumDir, args.Load, args.Verbose)
	return err
}

func AddSockopsSensors(parser v1alpha1.ParserPolicySpec) (*sensors.Sensor, error) {
	if (parser.Tls.Enable && parser.Tls.Mode == "socket") ||
		parser.Http.Enable ||
		parser.Nop.Enable {
		return builder("__sockops__sensors__")
	}
	return nil, nil
}
func (*sockopsSensor) SpecHandler(raw interface{}) (*sensors.Sensor, error) {
	spec := raw.(*v1alpha1.TracingPolicySpec)
	return AddSockopsSensors(spec.Parser)
}

func SetFilter(mapDir string, mapName string, selectors [128]byte) error {
	selectorMap, err := ebpf.LoadPinnedMap(filepath.Join(mapDir, mapName), nil)
	if err != nil {
		return fmt.Errorf("failed to open selector map '%s': %w", mapName, err)
	}
	defer selectorMap.Close()

	return selectorMap.Update(uint32(0), selectors, ebpf.UpdateAny)
}
