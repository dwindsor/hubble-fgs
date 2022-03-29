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
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
)

var (
	// Needed on both the HTTP and TLS programs.
	SockopsEstablished = sensors.ProgramBuilder(
		"bpf_sockops.o",
		"sockops",
		"sockops/fgs_sockops",
		"sockops_fgs_sockops",
		"sockops")

	TlsSockMapName  = "tls_sock_map"
	httpSockMapName = "http_sock_map"
	NopSockMapName  = "nop_sock_map"

	HttpSockMap   = sensors.MapBuilder(httpSockMapName, SockopsEstablished)
	TlsSockMap    = sensors.MapBuilder(TlsSockMapName, SockopsEstablished)
	NopSockMap    = sensors.MapBuilder(NopSockMapName, SockopsEstablished)
	TlsFilterMap  = sensors.MapBuilder("tls_filter_map", SockopsEstablished)
	HttpFilterMap = sensors.MapBuilder("http_filter_map", SockopsEstablished)
	NopFilterMap  = sensors.MapBuilder("nop_filter_map", SockopsEstablished)
)

func init() {
	sockops := &sockopsSensor{
		name: "sockops loader",
	}
	sensors.RegisterProbeType("sockops", sockops)
	sensors.RegisterTracingSensorsAtInit(sockops.name, sockops)
}

func builder(name string) (*sensors.Sensor, error) {
	var progs []*sensors.Program
	var maps []*sensors.Map

	if kernels.MinKernelVersion("5.8.0") {
		logger.GetLogger().Infof("Enable Sockops")
		progs = append(progs, SockopsEstablished)
		maps = append(maps,
			HttpSockMap, TlsSockMap, NopSockMap,
			HttpFilterMap, TlsFilterMap, NopFilterMap)

		return sensors.SensorBuilder("__sockops_sensors__", progs, maps), nil
	}
	return nil, nil
}

type sockopsSensor struct {
	name string
}

func (*sockopsSensor) LoadProbe(args sensors.LoadProbeArgs) (error, int) {
	err := sensors.LoadCgroupProgram(args.BPFDir, args.MapDir, args.CiliumDir, args.Load)
	return err, -1
}

func AddSockopsSensors(parser v1alpha1.ParserPolicySpec) (*sensors.Sensor, error) {
	if (parser.Tls.Enable && parser.Tls.Mode == "socket") ||
		parser.Http.Enable ||
		parser.Nop.Enable {
		return builder("__sockops__sensors__")
	}
	return nil, nil
}
func (*sockopsSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
	return AddSockopsSensors(spec.Parser)
}
