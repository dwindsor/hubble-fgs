//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package layer3

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/icmp"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/ip"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/rawsock"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/tcp"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/udp"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/tcpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/udpconfig"
	"github.com/isovalent/hubble-fgs/pkg/sensors/networklatency"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/cgroup"
	"github.com/isovalent/hubble-fgs/pkg/sensors/socktrack"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
	"golang.org/x/sys/unix"
)

var (
	cgrp_ingress_configured = false
	cgrp_egress_configured  = false
	configured              = false
	tcpEnabled              = false
	udpEnabled              = false
	dnsEnabled              = false
	icmpEnabled             = false
	rawEnabled              = false

	lastInitProg   *program.Program
	firstStatsProg *program.Program
)

var (
	CgroupProtocolConfigMapName = "tg_cgroup_protocol_cfg_map"
)

func unloadLayer3Sensor() error {
	// We want to make sure we stand configuration up when loading/unloading the sensor.
	cgrp_ingress_configured = false
	cgrp_egress_configured = false
	configured = false
	if tcpEnabled {
		err := tcp.UnloadSensor()
		if err != nil {
			return err
		}
		tcpEnabled = false
	}
	if udpEnabled {
		err := udp.UnloadSensor()
		if err != nil {
			return err
		}
		udpEnabled = false
	}
	if icmpEnabled {
		err := icmp.UnloadSensor()
		if err != nil {
			return err
		}
		icmpEnabled = false
	}
	if rawEnabled {
		err := rawsock.UnloadSensor()
		if err != nil {
			return err
		}
		rawEnabled = false
	}

	mapDir := bpf.MapPrefixPath()
	cfgMapName := path.Join(path.Dir(mapDir), CgroupProtocolConfigMapName)
	os.Remove(cfgMapName)

	return nil
}

var (
	EgressDispatcher = program.Builder(
		"bpf_cgroup_net.o",
		"cgroup_egress",
		"cgroup_skb/egress",
		"tg_cgroup_egress",
		"cgrp_egress",
	)

	EgressDispatcherSkbLoad = program.Builder(
		"bpf_cgroup_net_load.o",
		"cgroup_egress",
		"cgroup_skb/egress",
		"tg_cgroup_egress",
		"cgrp_egress",
	)

	EgressDispatcherSkbLoad54 = program.Builder(
		"bpf_cgroup_net_load_5-4.o",
		"cgroup_egress",
		"cgroup_skb/egress",
		"tg_cgroup_egress",
		"cgrp_egress",
	)

	IngressDispatcher = program.Builder(
		"bpf_cgroup_net.o",
		"cgroup_ingress",
		"cgroup_skb/ingress",
		"tg_cgroup_ingress",
		"cgrp_ingress",
	)

	IngressDispatcherSkbLoad = program.Builder(
		"bpf_cgroup_net_load.o",
		"cgroup_ingress",
		"cgroup_skb/ingress",
		"tg_cgroup_ingress",
		"cgrp_ingress",
	)

	IngressDispatcherSkbLoad54 = program.Builder(
		"bpf_cgroup_net_load_5-4.o",
		"cgroup_ingress",
		"cgroup_skb/ingress",
		"tg_cgroup_ingress",
		"cgrp_ingress",
	)

	dispatcherProgs          = []*program.Program{EgressDispatcher, IngressDispatcher}
	dispatcherSkbLoadProgs   = []*program.Program{EgressDispatcherSkbLoad, IngressDispatcherSkbLoad}
	dispatcherSkbLoad54Progs = []*program.Program{EgressDispatcherSkbLoad54, IngressDispatcherSkbLoad54}

	// Dispatcher protocol configuration map
	protoCfgMap          = program.MapBuilder("tg_cgroup_protocol_cfg_map", EgressDispatcher)
	protoCfgSkbLoadMap   = program.MapBuilder("tg_cgroup_protocol_cfg_map", EgressDispatcherSkbLoad)
	protoCfgSkbLoad54Map = program.MapBuilder("tg_cgroup_protocol_cfg_map", EgressDispatcherSkbLoad54)

	// Dispatcher Latency maps
	latencyConfigMap        = program.MapBuilder(networklatency.ConfigMapName, IngressDispatcher)
	latencyConfigSkbLoadMap = program.MapBuilder(networklatency.ConfigMapName, IngressDispatcherSkbLoad54)

	// Dispatcher UDP maps
	udpMap          = program.MapBuilder(udp.UdpMapName, EgressDispatcher)
	udpMapSkbLoad   = program.MapBuilder(udp.UdpMapName, EgressDispatcherSkbLoad)
	udpMapSkbLoad54 = program.MapBuilder(udp.UdpMapName, EgressDispatcherSkbLoad54)

	udpMapStats          = program.MapBuilder(udpconfig.UdpMapStatsName, EgressDispatcher)
	udpMapStatsSkbLoad   = program.MapBuilder(udpconfig.UdpMapStatsName, EgressDispatcherSkbLoad)
	udpMapStatsSkbLoad54 = program.MapBuilder(udpconfig.UdpMapStatsName, EgressDispatcherSkbLoad54)

	udpConfigMap          = program.MapBuilder(udp.ConfigMapName, EgressDispatcher)
	udpConfigSkbLoadMap   = program.MapBuilder(udp.ConfigMapName, EgressDispatcherSkbLoad)
	udpConfigSkbLoad54Map = program.MapBuilder(udp.ConfigMapName, EgressDispatcherSkbLoad54)

	udpPayloadMap          = program.MapBuilder(udp.UdpPayloadMapName, EgressDispatcher)
	udpPayloadSkbLoadMap   = program.MapBuilder(udp.UdpPayloadMapName, EgressDispatcherSkbLoad)
	udpPayloadSkbLoad54Map = program.MapBuilder(udp.UdpPayloadMapName, EgressDispatcherSkbLoad54)

	udpMaps          = []*program.Map{udpMap, udpMapStats, udpConfigMap, udpPayloadMap, latencyConfigMap}
	udpMapsSkbLoad   = []*program.Map{udpMapSkbLoad, udpMapStatsSkbLoad, udpConfigSkbLoadMap, udpPayloadSkbLoadMap, latencyConfigSkbLoadMap}
	udpMapsSkbLoad54 = []*program.Map{udpMapSkbLoad54, udpMapStatsSkbLoad54, udpConfigSkbLoad54Map, udpPayloadSkbLoad54Map, latencyConfigSkbLoadMap}

	// Process Tree maps
	DestinationEndpointEgressMap    = program.MapUser("destination_endpoint_map", EgressDispatcher)
	DestinationEndpointIngressMap   = program.MapUser("destination_endpoint_map", IngressDispatcher)
	ListenEndpointEgressMap         = program.MapUser("listen_endpoint_map", EgressDispatcher)
	ListenEndpointIngressMap        = program.MapUser("listen_endpoint_map", IngressDispatcher)
	ProcessTreeBinaryUUIDEgressMap  = program.MapUser("process_tree_binary_uid_map", EgressDispatcher)
	ProcessTreeBinaryUUIDIngressMap = program.MapUser("process_tree_binary_uid_map", IngressDispatcher)
	BpfEndpointIdEgressMap          = program.MapUser("tg_bpf_endpoint_id_map", EgressDispatcher)
	BpfEndpointIdIngressMap         = program.MapUser("tg_bpf_endpoint_id_map", IngressDispatcher)
	EndpointIdEgressMap             = program.MapUser("tg_endpoint_id_map", EgressDispatcher)
	EndpointIdIngressMap            = program.MapUser("tg_endpoint_id_map", IngressDispatcher)

	// DNS Parser maps
	// Those maps are only used within the DNS parser that is included in the dispatcher and we assume >=5.15
	DNSParserErrorMap = program.MapBuilder(dnsparser.ErrorMapName, IngressDispatcher, EgressDispatcher)
	DNSDomainMap      = program.MapBuilder(dnsparser.DomainToIDMapName, IngressDispatcher, EgressDispatcher)
	DNSDomainMapRev   = program.MapBuilder(dnsparser.IDToDomainMapName, IngressDispatcher, EgressDispatcher)
	DNSGlobalIDMap    = program.MapBuilder(dnsparser.GlobalDNSIDMapName, IngressDispatcher, EgressDispatcher)
	// This map is shared between the DNS parser and the process tree: the fdlookup and tcpsockops progs
	DNSEndpointIDMap = program.MapBuilder(dnsparser.DNSEndpointIDMapName, IngressDispatcher, EgressDispatcher, ip.FdLookupFentry_5_15, ip.FdLookupKprobe_5_15, tcp.TcpSockops515)

	// Dispatcher all maps
	dispatcherMaps = append(udpMaps,
		[]*program.Map{protoCfgMap,
			DestinationEndpointIngressMap,
			DestinationEndpointEgressMap,
			ListenEndpointIngressMap,
			ListenEndpointEgressMap,
			ProcessTreeBinaryUUIDEgressMap,
			ProcessTreeBinaryUUIDIngressMap,
			BpfEndpointIdEgressMap,
			BpfEndpointIdIngressMap,
			EndpointIdEgressMap,
			EndpointIdIngressMap,
		}...)
	dispatcherSkbLoadMaps   = append(udpMapsSkbLoad, protoCfgSkbLoadMap)
	dispatcherSkbLoad54Maps = append(udpMapsSkbLoad54, protoCfgSkbLoad54Map)
)

func EnableLayer3(policy tracingpolicy.TracingPolicy, tcpTimestampEnable, cgroup, udpTimestampEnable bool,
	udpInterval time.Duration, reportRawClose bool) *sensors.Sensor {
	// We want to make sure we stand configuration up when loading/unloading the sensor.
	cgrp_ingress_configured = false
	cgrp_egress_configured = false
	configured = false
	needDispatcher := false

	progsInitSock, maps := socktrack.EnableSocktrack()
	fdLookupProgs, fdLookupMaps := ip.Enable()
	progsInitSock = append(progsInitSock, fdLookupProgs...)
	maps = append(maps, fdLookupMaps...)
	var progsCollectStats []*program.Program

	if tcpEnabled {
		tcpProgsInit, tcpProgsStats, tcpMaps := tcp.EnableTcp(tcpTimestampEnable)
		progsInitSock = append(progsInitSock, tcpProgsInit...)
		progsCollectStats = append(progsCollectStats, tcpProgsStats...)
		maps = append(maps, tcpMaps...)
		needDispatcher = true
	}
	if udpEnabled {
		udpProgsInit, udpProgsStats, udpMaps := udp.EnableUdp(cgroup, udpTimestampEnable, udpInterval)
		progsInitSock = append(progsInitSock, udpProgsInit...)
		progsCollectStats = append(progsCollectStats, udpProgsStats...)
		maps = append(maps, udpMaps...)
		needDispatcher = true
	}
	if icmpEnabled {
		icmpProgsInit, icmpProgsStats, icmpMaps := icmp.EnableIcmp()
		progsInitSock = append(progsInitSock, icmpProgsInit...)
		progsCollectStats = append(progsCollectStats, icmpProgsStats...)
		maps = append(maps, icmpMaps...)
		needDispatcher = true
	}
	if rawEnabled {
		rawProgsInit, rawProgsStats, rawMaps := rawsock.EnableRawsock()
		progsInitSock = append(progsInitSock, rawProgsInit...)
		progsCollectStats = append(progsCollectStats, rawProgsStats...)
		maps = append(maps, rawMaps...)
		needDispatcher = true
	}
	if dnsEnabled {
		if enterpriseOption.Config.EnableBPFDNSParser {
			DNSEndpointIDMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
			DNSDomainMapRev.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
			if enterpriseOption.Config.EnableProcessTree {
				DNSDomainMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
			}
		}

		maps = append(maps, DNSParserErrorMap)
		maps = append(maps, DNSEndpointIDMap)
		maps = append(maps, DNSDomainMap)
		maps = append(maps, DNSDomainMapRev)
		maps = append(maps, DNSGlobalIDMap)
	}

	if needDispatcher == true {
		if kernels.MinKernelVersion("5.4.0") {
			if !kernels.MinKernelVersion("5.5.0") {
				progsCollectStats = append(progsCollectStats, dispatcherSkbLoad54Progs...)
				maps = append(maps, dispatcherSkbLoad54Maps...)
			} else if !kernels.MinKernelVersion("5.14.0") {
				progsCollectStats = append(progsCollectStats, dispatcherSkbLoadProgs...)
				maps = append(maps, dispatcherSkbLoadMaps...)
			} else {
				if runtime.GOARCH != "amd64" {
					progsCollectStats = append(progsCollectStats, dispatcherSkbLoadProgs...)
					maps = append(maps, dispatcherSkbLoadMaps...)
				} else {
					progsCollectStats = append(progsCollectStats, dispatcherProgs...)
					maps = append(maps, dispatcherMaps...)
				}
			}
		} else {
			logger.GetLogger().Info("Cgroup hooks requires 5.4+ kernels using Kprobes")
		}
	}
	// If UDP is enabled then we need close events reported to maintain our maps.
	configureSettings(rawEnabled, reportRawClose, udpEnabled)

	// We want progsInitSock to load first, then socket discovery, then progsCollectStats. This will ensure that
	// we don't miss a socket, but we might see the same socket in both an init prog and in socket discovery. We
	// will make sure that's not a problem by ensuring socket discovery updates the map entry with the same info.
	// In terms of programs loading, we simply have LoadProbe called for all programs for which we've registered
	// loaders for their types. We therefore make all our programs have novel types so every one hits our
	// LoadProbe. Then if progsInitSock is not empty, we note its last program; after that program is loaded, we
	// call socket discovery. If progsInitSock is empty, then we note the first program of progsCollectStats and
	// call socket discovery before that program loads.
	if len(progsInitSock) > 0 {
		lastInitProg = progsInitSock[len(progsInitSock)-1]
		firstStatsProg = nil
	} else {
		lastInitProg = nil
		if len(progsCollectStats) > 0 {
			firstStatsProg = progsCollectStats[0]
		} else {
			firstStatsProg = nil
		}
	}

	l3Sensor := sensors.SensorBuilder(policy, api.Layer3SensorName, append(progsInitSock, progsCollectStats...), maps)
	l3Sensor.PreUnloadHook = unloadLayer3Sensor
	return l3Sensor
}

type l3Sensor struct {
	name string
}

func (l3 *l3Sensor) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	fid policyfilter.PolicyID,
) (sensors.SensorIface, error) {
	spec := policy.TpSpec()
	if !spec.Parser.Tcp.Enable && !spec.Parser.Udp.Enable && !spec.Parser.Dns.Enable && !spec.Parser.Icmp.Enable && !spec.Parser.Rawsock.Enable {
		return nil, nil
	}

	if fid != policyfilter.NoFilterID {
		return nil, fmt.Errorf("layer3 sensor does not implement policy filtering")
	}

	tcpEnabled = spec.Parser.Tcp.Enable
	udpEnabled = spec.Parser.Udp.Enable
	dnsEnabled = spec.Parser.Dns.Enable
	icmpEnabled = spec.Parser.Icmp.Enable
	rawEnabled = spec.Parser.Rawsock.Enable
	udpCgroup := spec.Parser.Udp.Cgroup
	// If TCP or UDP then turn on DNS as nobody wants L4 without DNS.
	if tcpEnabled || udpEnabled {
		dnsEnabled = true
		// DNS requires cgroup programs.
		udpCgroup = true
	}
	// If DNS then turn on UDP otherwise DNS doesn't work.
	if dnsEnabled {
		udpEnabled = true
		// DNS requires cgroup programs.
		udpCgroup = true
	}
	// However, disable cgroup and therefore DNS if the kernel is too old
	if !kernels.MinKernelVersion("5.4.0") {
		udpCgroup = false
		dnsEnabled = false
	}
	tcpTimestampEnable := false
	var err error
	if tcpEnabled {
		tcpTimestampEnable, err = tcp.PolicyHandler(spec)
		if err != nil {
			return nil, fmt.Errorf("tcp.PolicyHandler error: %w", err)
		}
	}

	udpTimestampEnable := false
	var udpInterval time.Duration
	if udpEnabled {
		udpTimestampEnable, udpInterval, err = udp.PolicyHandler(spec)
		if err != nil {
			return nil, fmt.Errorf("udp.PolicyHandler error: %w", err)
		}
	}

	if icmpEnabled {
		err = icmp.PolicyHandler(spec)
		if err != nil {
			return nil, fmt.Errorf("icmp.PolicyHandler error: %w", err)
		}
		// ICMP partially relies on raw socket tracking.
		rawEnabled = true
	}

	reportRawClose := false
	if rawEnabled {
		reportRawClose, err = rawsock.PolicyHandler(spec)
		if err != nil {
			return nil, fmt.Errorf("rawsock.PolicyHandler error: %w", err)
		}
	}

	return EnableLayer3(policy, tcpTimestampEnable,
		udpCgroup, udpTimestampEnable, udpInterval, reportRawClose), nil
}

type CgroupProtocolConfigValue struct {
	icmp4Enabled uint32
	icmp6Enabled uint32
	tcp4Enabled  uint32
	tcp6Enabled  uint32
	udp4Enabled  uint32
	udp6Enabled  uint32
}

func (v *CgroupProtocolConfigValue) String() string {
	return fmt.Sprintf("CgroupProtocolConfigValue: "+
		"icmp4Enabled: %d, "+
		"icmp6Enabled: %d, "+
		"tcp4Enabled: %d, "+
		"tcp6Enabled: %d, "+
		"udp4Enabled: %d, "+
		"udp6Enabled: %d",
		v.icmp4Enabled,
		v.icmp6Enabled,
		v.tcp4Enabled,
		v.tcp6Enabled,
		v.udp4Enabled,
		v.udp6Enabled,
	)
}

type CgroupProtocolConfigKey struct {
	Zero uint32
}

func (k *CgroupProtocolConfigKey) String() string {
	return fmt.Sprintf("Zero: %d", k.Zero)
}

func (l3 *l3Sensor) createCgroupProtocolCfgMap(l3cfg CgroupProtocolConfigValue) error {
	zero := CgroupProtocolConfigKey{
		Zero: 0,
	}
	c := &ebpf.MapSpec{
		Name:       CgroupProtocolConfigMapName,
		Type:       bpf.BPF_MAP_TYPE_ARRAY,
		KeySize:    uint32(unsafe.Sizeof(CgroupProtocolConfigKey{})),
		ValueSize:  uint32(unsafe.Sizeof(CgroupProtocolConfigValue{})),
		MaxEntries: 1,
		Pinning:    ebpf.PinByName,
	}
	opts := ebpf.MapOptions{
		PinPath: bpf.MapPrefixPath(),
	}

	cfgMap, err := ebpf.NewMapWithOptions(c, opts)
	if err != nil {
		return fmt.Errorf("failed `tg_cgroup_protocol_cfg_map` ebpf.NewMapWithOptions: %w", err)
	}
	defer cfgMap.Close()

	if err := cfgMap.Update(zero, l3cfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed cgroup_protocol_cfg_map Update: %w", err)
	}

	return nil
}

func (l3 *l3Sensor) configureMaps(args sensors.LoadProbeArgs) error {
	l3cfg := CgroupProtocolConfigValue{}

	if tcpEnabled {
		tcp.ConfigureMaps()
		l3cfg.tcp4Enabled = 1
		l3cfg.tcp6Enabled = 1
	}
	if udpEnabled {
		if err := udp.ConfigureMaps(args.BPFDir, udp.ConfigMapName, udp.Config); err != nil {
			return err
		}
		l3cfg.udp4Enabled = 1
		l3cfg.udp6Enabled = 1
	}
	if icmpEnabled {
		if err := icmp.ConfigureMaps(args.BPFDir, icmp.ConfigMapName, icmp.Config); err != nil {
			return err
		}
		l3cfg.icmp4Enabled = 1
		l3cfg.icmp6Enabled = 1
	}
	// Rawsock has no config maps.

	if icmpEnabled || tcpEnabled || udpEnabled {
		if err := l3.createCgroupProtocolCfgMap(l3cfg); err != nil {
			return err
		}
	}

	return nil
}

func configureSensor(args sensors.LoadProbeArgs) error {
	if tcpEnabled {
		tcp.ConfigureSensor()
		logger.GetLogger().WithField("timestampEnabled", udp.TimestampEnabled).Debug("TCP Loader")
		if tcp.TimestampEnabled {
			if err := networklatency.ConfigureLatency(args.BPFDir, unix.IPPROTO_TCP, tcpconfig.LatencyConfig); err != nil {
				logger.GetLogger().WithError(err).Warn("ConfigureLatency TCP")
				return err
			}
			networklatency.Start()
		}
	}
	if udpEnabled {
		udp.ConfigureSensor()
		logger.GetLogger().WithField("timestampEnabled", udp.TimestampEnabled).Debug("UDP Loader")
		if udp.TimestampEnabled {
			if err := networklatency.ConfigureLatency(args.BPFDir, unix.IPPROTO_UDP, udpconfig.LatencyConfig); err != nil {
				return err
			}
			networklatency.Start()
		}
	}
	if icmpEnabled {
		icmp.ConfigureSensor()
	}
	if rawEnabled {
		rawsock.ConfigureSensor()
	}

	return nil
}

func (l3 *l3Sensor) LoadProbe(args sensors.LoadProbeArgs) error {
	// Configure maps when the first program is loaded.
	if !configured {
		l3.configureMaps(args)
		configured = true
	}

	// If this is the first of the collect stats programs, discover sockets.
	if args.Load == firstStatsProg {
		firstStatsProg = nil
		err := configureSensor(args)
		if err != nil {
			return err
		}
	}

	switch args.Load.Type {
	case "cgrp_ingress":
		if cgrp_ingress_configured {
			break
		}
		cgrp_ingress_configured = true
		err := cgroup.LoadCgroupProgram(args.BPFDir, args.Load, args.Verbose)
		if err != nil {
			logger.GetLogger().WithError(err).Warn("CGRP")
			return err
		}
	case "cgrp_egress":
		if cgrp_egress_configured {
			break
		}
		cgrp_egress_configured = true
		err := cgroup.LoadCgroupProgram(args.BPFDir, args.Load, args.Verbose)
		if err != nil {
			logger.GetLogger().WithError(err).Warn("CGRP")
			return err
		}
	case "cgrp_inet4_bind", "cgrp_inet6_bind":
		err := cgroup.LoadCgroupProgram(args.BPFDir, args.Load, args.Verbose)
		if err != nil {
			logger.GetLogger().WithError(err).Warn("CGRP")
			return err
		}
	case "tc_egress":
		err := networklatency.AttachTc(args)
		if err != nil {
			logger.GetLogger().WithError(err).Warn("TC_EGRESS")
			return err
		}
	case "tcp_fentry", "udp_fentry", "icmp_fentry", "rawsock_fentry", "socktrack_fentry":
		err := program.LoadTracingProgram(args.BPFDir, args.Load, args.Verbose)
		if err != nil {
			logger.GetLogger().WithError(err).Warn("FENTRY")
			return err
		}
	case "layer3_sensor":
		var err error
		if args.Load.Attach == "sockops" {
			err = cgroup.LoadCgroupProgram(args.BPFDir, args.Load, args.Verbose)
		} else if args.Load.Attach == "fentry" {
			err = program.LoadTracingProgram(args.BPFDir, args.Load, args.Verbose)
		} else {
			err = program.LoadKprobeProgram(args.BPFDir, args.Load, args.Verbose)
		}
		if err != nil {
			logger.GetLogger().WithError(err).Warn("LAYER3_SENSOR")
			return err
		}
	}

	// If this is the last of the init progs, discover sockets.
	if args.Load == lastInitProg {
		lastInitProg = nil
		err := configureSensor(args)
		if err != nil {
			return err
		}
	}

	return nil
}

func init() {
	AddLayer3()
}

func AddLayer3() {
	err := tcp.Init()
	if err != nil {
		logger.GetLogger().WithError(err).Errorf("TCP init failed. Disabling Layer3")
		return
	}

	err = udp.Init()
	if err != nil {
		logger.GetLogger().WithError(err).Errorf("UDP init failed. Disabling Layer3")
		return
	}

	err = icmp.Init()
	if err != nil {
		logger.GetLogger().WithError(err).Errorf("ICMP init failed. Disabling Layer3")
		return
	}

	err = rawsock.Init()
	if err != nil {
		logger.GetLogger().WithError(err).Errorf("RAW init failed. Disabling Layer3")
		return
	}

	l3 := &l3Sensor{
		name: "Layer3 sensor",
	}

	sensors.RegisterPolicyHandlerAtInit(l3.name, l3)

	sensors.RegisterProbeType("layer3_sensor", l3)
	sensors.RegisterProbeType("layer3Sockops", l3)
	sensors.RegisterProbeType("cgrp_ingress", l3)
	sensors.RegisterProbeType("cgrp_egress", l3)
	sensors.RegisterProbeType("cgrp_inet4_bind", l3)
	sensors.RegisterProbeType("cgrp_inet6_bind", l3)
	sensors.RegisterProbeType("tc_egress", l3)
	sensors.RegisterProbeType("tcp_fentry", l3)
	sensors.RegisterProbeType("udp_fentry", l3)
	sensors.RegisterProbeType("icmp_fentry", l3)
	sensors.RegisterProbeType("rawsock_fentry", l3)
	sensors.RegisterProbeType("socktrack_fentry", l3)

	observer.RegisterEventHandlerAtInit(ops.MSG_OP_IP_ERROR, ip.HandleIpError)
}

func HTTPContext() *program.Map {
	return tcp.HTTPContext
}

func SocketMap() *program.Map {
	if utils.SupportFentry() {
		return tcp.SocketMapFentry
	}
	return tcp.SocketMapKprobe
}

func SocketStats() *program.Map {
	return tcp.SocketStats
}

func TcpSocketMap() *program.Map {
	if utils.SupportFentry() {
		return tcp.TcpSocketMapFentry
	}
	return tcp.TcpSocketMapKprobe
}

func TcpSocketStats() *program.Map {
	return tcp.TcpSocketStats
}

func TLSContext() *program.Map {
	return tcp.TLSContext
}

func TLSMapStats() *program.Map {
	if utils.SupportFentry() {
		return tcp.TLSMapStatsFentry
	}
	return tcp.TLSMapStatsKprobe
}

func TLSBottles() *program.Map {
	return tcp.TLSBottles
}

func TLSBottleStats() *program.Map {
	return tcp.TLSBottleStats
}
