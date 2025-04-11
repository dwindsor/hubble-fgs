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
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
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
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
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
	reportRawClose          = false
	udpCGroup               = false

	lastInitProg   *program.Program
	firstStatsProg *program.Program
)

var (
	baseLayer3Policy            = "__base_layer3__"
	CgroupProtocolConfigMapName = "tg_cgroup_protocol_cfg_map"
)

func unloadLayer3Sensor(policy tracingpolicy.TracingPolicy) error {
	// We want to make sure we stand configuration up when loading/unloading the programs.
	if !enterpriseOption.Config.Layer3CLIEnable {
		cgrp_ingress_configured = false
		cgrp_egress_configured = false
		configured = false
	}
	if tcpEnabled {
		err := tcp.UnloadSensor(policy)
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
	protoCfgMap          = program.MapBuilder(CgroupProtocolConfigMapName, EgressDispatcher)
	protoCfgSkbLoadMap   = program.MapBuilder(CgroupProtocolConfigMapName, EgressDispatcherSkbLoad)
	protoCfgSkbLoad54Map = program.MapBuilder(CgroupProtocolConfigMapName, EgressDispatcherSkbLoad54)

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
			// Process Tree maps
			program.MapUserFrom(base.DestinationEndpointMap),
			program.MapUserFrom(base.ListenEndpointMap),
			program.MapUserFrom(base.ProcessTreeBinaryUUIDMap),
			program.MapUserFrom(base.BpfEndpointIdMap),
			program.MapUserFrom(base.EndpointIdMap),
		}...)
	dispatcherSkbLoadMaps   = append(udpMapsSkbLoad, protoCfgSkbLoadMap)
	dispatcherSkbLoad54Maps = append(udpMapsSkbLoad54, protoCfgSkbLoad54Map)
)

func ProgsAndMaps(tcpTimestampEnable, cgroup, udpTimestampEnable bool) ([]*program.Program, []*program.Map) {
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
		udpProgsInit, udpProgsStats, udpMaps := udp.EnableUdp(cgroup, udpTimestampEnable)
		progsInitSock = append(progsInitSock, udpProgsInit...)
		progsCollectStats = append(progsCollectStats, udpProgsStats...)
		maps = append(maps, udpMaps...)
		needDispatcher = true

		// For now, the DNS parser is loaded alongside the UDP sensor
		if enterpriseOption.Config.EnableBPFDNSParser {
			logger.GetLogger().Info("Enabling the BPF DNS parser")
			DNSEndpointIDMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
			DNSDomainMapRev.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
			if enterpriseOption.Config.EnableProcessTree {
				DNSDomainMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
			}

			maps = append(maps, DNSParserErrorMap)
			maps = append(maps, DNSEndpointIDMap)
			maps = append(maps, DNSDomainMap)
			maps = append(maps, DNSDomainMapRev)
			maps = append(maps, DNSGlobalIDMap)
		}
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

	if needDispatcher {
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

	maps = append(maps, program.MapUserFrom(base.ExecveMap))

	return append(progsInitSock, progsCollectStats...), maps
}

func (l3 *l3Sensor) enableLayer3(policy tracingpolicy.TracingPolicy, tcpTimestampEnable, cgroup, udpTimestampEnable bool,
	udpInterval time.Duration) *sensors.Sensor {
	spec := policy.TpSpec()

	// We want to make sure we stand configuration up when loading/unloading the sensor.
	cgrp_ingress_configured = false
	cgrp_egress_configured = false
	configured = false
	var progs []*program.Program
	var maps []*program.Map

	if !enterpriseOption.Config.Layer3CLIEnable {
		progs, maps = ProgsAndMaps(tcpTimestampEnable, cgroup, udpTimestampEnable)
	} else {
		// If we are loading programs (!Layer3CLIEnable) then the sensor will be configured at the
		// appropriate point. As we're not, configure the sensor now.
		l3.configureMaps(spec)
	}

	udp.SetGcInterval(udpInterval)

	l3Sensor := sensors.SensorBuilder(policy, api.Layer3SensorName, progs, maps)
	l3Sensor.PreUnloadHook = func() error {
		unloadLayer3Sensor(policy)
		return nil
	}
	return l3Sensor
}

type l3Sensor struct {
	name string
}

func hasCgroup() bool {
	return kernels.MinKernelVersion("5.4.0")
}

func (l3 *l3Sensor) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	fid policyfilter.PolicyID,
) (sensors.SensorIface, error) {
	spec := policy.TpSpec()

	if spec.Parser.Tcp == nil && spec.Parser.Udp == nil && spec.Parser.Icmp == nil && spec.Parser.Rawsock == nil {
		return nil, nil
	}

	if fid != policyfilter.NoFilterID {
		return nil, fmt.Errorf("layer3 sensor does not implement policy filtering")
	}

	// Check if a protocol enable has been set in policy and warn that this is deprecated.
	if (spec.Parser.Tcp != nil && spec.Parser.Tcp.Enable) || (spec.Parser.Udp != nil && spec.Parser.Udp.Enable) || spec.Parser.Dns.Enable ||
		(spec.Parser.Icmp != nil && spec.Parser.Icmp.Enable) || (spec.Parser.Rawsock != nil && spec.Parser.Rawsock.Enable) {
		logger.GetLogger().Info("CLI switches (--enable-tcp, --enable-udp, etc) are preferred over protocol enabling in policies. We recommend using CLI switches and removing protocol enabling in policies.")
	}

	udpCgroup := true
	if !enterpriseOption.Config.Layer3CLIEnable {
		if spec.Parser.Tcp != nil {
			tcpEnabled = spec.Parser.Tcp.Enable
		}
		if spec.Parser.Udp != nil {
			udpEnabled = spec.Parser.Udp.Enable
		}
		if spec.Parser.Icmp != nil {
			icmpEnabled = spec.Parser.Icmp.Enable
		}
		if spec.Parser.Rawsock != nil {
			rawEnabled = spec.Parser.Rawsock.Enable
		}
		dnsEnabled = spec.Parser.Dns.Enable
		// If TCP or UDP then turn on DNS as nobody wants L4 without DNS.
		if tcpEnabled || udpEnabled {
			dnsEnabled = true
			// DNS requires cgroup programs.
			udpCgroup = true
		}
		if dnsEnabled {
			udpEnabled = true
			// DNS requires cgroup programs.
			udpCgroup = true
		}
	}
	// However, disable cgroup and therefore DNS if unavailable.
	if !hasCgroup() {
		logger.GetLogger().Warn("Kernel does not provide suitable CGroup/SKB support. Falling back to kprobes and disabling DNS.")
		udpCgroup = false
		dnsEnabled = false
	}
	tcpTimestampEnable := false
	var err error
	if spec.Parser.Tcp != nil && tcpEnabled {
		tcpTimestampEnable, err = tcp.PolicyHandler(spec)
		if err != nil {
			return nil, fmt.Errorf("tcp.PolicyHandler error: %w", err)
		}
	}

	udpTimestampEnable := false
	var udpInterval time.Duration
	if spec.Parser.Udp != nil && udpEnabled {
		udpTimestampEnable, udpInterval, err = udp.PolicyHandler(spec)
		if err != nil {
			return nil, fmt.Errorf("udp.PolicyHandler error: %w", err)
		}
	}

	if spec.Parser.Icmp != nil && icmpEnabled {
		err = icmp.PolicyHandler(spec)
		if err != nil {
			return nil, fmt.Errorf("icmp.PolicyHandler error: %w", err)
		}
	}

	if spec.Parser.Rawsock != nil && rawEnabled {
		reportRawClose, err = rawsock.PolicyHandler(spec)
		if err != nil {
			return nil, fmt.Errorf("rawsock.PolicyHandler error: %w", err)
		}
	}

	return l3.enableLayer3(policy, tcpTimestampEnable,
		udpCgroup, udpTimestampEnable, udpInterval), nil
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

func (l3 *l3Sensor) configureCgroupProtocolCfgMap(l3cfg CgroupProtocolConfigValue) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(bpf.MapPrefixPath(), CgroupProtocolConfigMapName), nil)
	if err != nil {
		return err
	}
	defer m.Close()

	key := &CgroupProtocolConfigKey{
		Zero: uint32(0),
	}
	err = m.Put(key, &l3cfg)
	if err != nil {
		return fmt.Errorf("failed cgroup_protocol_cfg_map Update: %w", err)
	}

	return nil
}

func (l3 *l3Sensor) configureMaps(spec *v1alpha1.TracingPolicySpec) error {
	l3cfg := CgroupProtocolConfigValue{}

	// If UDP is enabled then we need close events reported to maintain our maps.
	configureSettings(rawEnabled, reportRawClose, udpEnabled)

	if tcpEnabled && (spec == nil || spec.Parser.Tcp != nil) {
		tcp.ConfigureMaps()
		l3cfg.tcp4Enabled = 1
		l3cfg.tcp6Enabled = 1
	}
	if udpEnabled && (spec == nil || spec.Parser.Udp != nil) {
		if err := udp.ConfigureMaps(bpf.MapPrefixPath(), udp.ConfigMapName, udp.Config); err != nil {
			return err
		}
		l3cfg.udp4Enabled = 1
		l3cfg.udp6Enabled = 1
	}
	if icmpEnabled && (spec == nil || spec.Parser.Icmp != nil) {
		if err := icmp.ConfigureMaps(bpf.MapPrefixPath(), icmp.ConfigMapName, icmp.Config); err != nil {
			return err
		}
		l3cfg.icmp4Enabled = 1
		l3cfg.icmp6Enabled = 1
	}
	// Rawsock has no config maps.

	if icmpEnabled || tcpEnabled || udpEnabled {
		if err := l3.configureCgroupProtocolCfgMap(l3cfg); err != nil {
			return err
		}
	}

	return nil
}

func (l3 *l3Sensor) configureSensor() error {
	if tcpEnabled {
		tcp.ConfigureSensor()
		logger.GetLogger().WithField("timestampEnabled", udp.TimestampEnabled).Debug("TCP Loader")
		if tcp.TimestampEnabled {
			if err := networklatency.ConfigureLatency(unix.IPPROTO_TCP, tcpconfig.LatencyConfig); err != nil {
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
			if err := networklatency.ConfigureLatency(unix.IPPROTO_UDP, udpconfig.LatencyConfig); err != nil {
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
		l3.configureMaps(nil)
		configured = true
	}

	// If this is the first of the collect stats programs, discover sockets.
	if args.Load == firstStatsProg {
		firstStatsProg = nil
		err := l3.configureSensor()
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
		err := cgroup.LoadCgroupProgram(args.BPFDir, args.Load, args.Maps, args.Verbose)
		if err != nil {
			logger.GetLogger().WithError(err).Warn("CGRP")
			return err
		}
	case "cgrp_egress":
		if cgrp_egress_configured {
			break
		}
		cgrp_egress_configured = true
		err := cgroup.LoadCgroupProgram(args.BPFDir, args.Load, args.Maps, args.Verbose)
		if err != nil {
			logger.GetLogger().WithError(err).Warn("CGRP")
			return err
		}
	case "cgrp_inet4_bind", "cgrp_inet6_bind":
		err := cgroup.LoadCgroupProgram(args.BPFDir, args.Load, args.Maps, args.Verbose)
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
		err := program.LoadTracingProgram(args.BPFDir, args.Load, args.Maps, args.Verbose)
		if err != nil {
			logger.GetLogger().WithError(err).Warn("FENTRY")
			return err
		}
	case "layer3_sensor":
		var err error
		switch args.Load.Attach {
		case "sockops":
			err = cgroup.LoadCgroupProgram(args.BPFDir, args.Load, args.Maps, args.Verbose)
		case "fentry":
			err = program.LoadTracingProgram(args.BPFDir, args.Load, args.Maps, args.Verbose)
		default:
			err = program.LoadKprobeProgram(args.BPFDir, args.Load, args.Maps, args.Verbose)
		}
		if err != nil {
			logger.GetLogger().WithError(err).Warn("LAYER3_SENSOR")
			return err
		}
	}

	// If this is the last of the init progs, discover sockets.
	if args.Load == lastInitProg {
		lastInitProg = nil
		err := l3.configureSensor()
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

func EnableLayer3Progs() error {
	if !enterpriseOption.Config.Layer3CLIEnable {
		return nil
	}
	if enterpriseOption.Config.EnableTCP {
		tcpEnabled = true
	}
	if enterpriseOption.Config.EnableUDP {
		udpEnabled = true
	}
	if enterpriseOption.Config.EnableICMP {
		icmpEnabled = true
	}
	if enterpriseOption.Config.EnableRawsock {
		rawEnabled = true
	}
	if enterpriseOption.Config.EnableDNS {
		dnsEnabled = true
		udp.InitDNS()
	}
	udpCGroup = true
	if !hasCgroup() {
		udpCGroup = false
		if dnsEnabled {
			return fmt.Errorf("enabling DNS requires CGroup support")
		}
	}
	return nil
}

func RunLayer3Progs(ctx context.Context) error {
	// By default, enable CGroup/SKB.
	progs, maps := ProgsAndMaps(enterpriseOption.Config.EnableLatency, udpCGroup, enterpriseOption.Config.EnableLatency)
	mgr := observer.GetSensorManager()
	initialLayer3Sensor := &sensors.Sensor{
		Name:  baseLayer3Policy,
		Progs: progs,
		Maps:  maps,
	}
	if err := mgr.AddSensor(ctx, initialLayer3Sensor.Name, initialLayer3Sensor); err != nil {
		return err
	}
	return mgr.EnableSensor(ctx, initialLayer3Sensor.Name)
}

func StartLayer3Progs(ctx context.Context) error {
	err := EnableLayer3Progs()
	if err != nil {
		return err
	}
	return RunLayer3Progs(ctx)
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
