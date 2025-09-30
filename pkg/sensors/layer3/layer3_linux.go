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
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"golang.org/x/sys/unix"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	"github.com/isovalent/hubble-fgs/pkg/manager"
	"github.com/isovalent/hubble-fgs/pkg/model/datapath"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	layer3cfg "github.com/isovalent/hubble-fgs/pkg/sensors/layer3/internal/config"
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

	BaseLoaded = false

	lastInitProg   *program.Program
	firstStatsProg *program.Program
)

func unloadLayer3Sensor(policy tracingpolicy.TracingPolicy) error {
	// We want to make sure we stand configuration up when loading/unloading the programs.
	config := networkapi.Layer3ConfigValue{}
	layer3cfg.SetConfig(&config, false, false, false)

	if !enterpriseOption.Config.Layer3CLIEnable {
		cgrp_ingress_configured = false
		cgrp_egress_configured = false
		configured = false
	}
	if tcpEnabled {
		err := tcp.UnloadSensor(&config, policy)
		if err != nil {
			return err
		}
		tcpEnabled = false
	}
	if udpEnabled {
		err := udp.UnloadSensor(&config)
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

	err := layer3cfg.UpdateMap(config)
	if err != nil {
		return fmt.Errorf("failed to write layer3 config to map: %w", err)
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

	EgressDispatcherNoProbeRead = program.Builder(
		"bpf_cgroup_net_no_probe_read.o",
		"cgroup_egress",
		"cgroup_skb/egress",
		"tg_cgroup_egress",
		"cgrp_egress",
	)

	EgressDispatcherProcessTree = program.Builder(
		"bpf_cgroup_net_pstree.o",
		"cgroup_egress",
		"cgroup_skb/egress",
		"tg_cgroup_egress",
		"cgrp_egress",
	)

	EgressDispatcherProcessTreeTimer = program.Builder(
		"bpf_cgroup_net_pstree_timer.o",
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

	IngressDispatcherNoProbeRead = program.Builder(
		"bpf_cgroup_net_no_probe_read.o",
		"cgroup_ingress",
		"cgroup_skb/ingress",
		"tg_cgroup_ingress",
		"cgrp_ingress",
	)

	IngressDispatcherProcessTree = program.Builder(
		"bpf_cgroup_net_pstree.o",
		"cgroup_ingress",
		"cgroup_skb/ingress",
		"tg_cgroup_ingress",
		"cgrp_ingress",
	)

	IngressDispatcherProcessTreeTimer = program.Builder(
		"bpf_cgroup_net_pstree_timer.o",
		"cgroup_ingress",
		"cgroup_skb/ingress",
		"tg_cgroup_ingress",
		"cgrp_ingress",
	)

	dispatcherProgs                 = []*program.Program{EgressDispatcher, IngressDispatcher}
	dispatcherNoProbeReadProgs      = []*program.Program{EgressDispatcherNoProbeRead, IngressDispatcherNoProbeRead}
	dispatcherProcessTreeProgs      = []*program.Program{EgressDispatcherProcessTree, IngressDispatcherProcessTree}
	dispatcherProcessTreeTimerProgs = []*program.Program{EgressDispatcherProcessTreeTimer, IngressDispatcherProcessTreeTimer}

	// Dispatcher Latency maps; could be problematic from an ownership perspective. Solve another day.
	latencyConfigMap = program.MapBuilder(networklatency.ConfigMapName, IngressDispatcher, IngressDispatcherNoProbeRead, IngressDispatcherProcessTree, IngressDispatcherProcessTreeTimer)

	// Dispatcher UDP maps, built here because they are only used by the dispatcher
	udpMap      = program.MapBuilder(udp.UdpMapName, EgressDispatcher, EgressDispatcherNoProbeRead, EgressDispatcherProcessTree, EgressDispatcherProcessTreeTimer)
	udpMapStats = program.MapBuilder(udpconfig.UdpMapStatsName, EgressDispatcher, EgressDispatcherNoProbeRead, EgressDispatcherProcessTree, EgressDispatcherProcessTreeTimer)
	udpTimerMap = program.MapBuilder(udp.UdpTimerMapName, EgressDispatcherProcessTreeTimer)
	udpMaps     = []*program.Map{udpMap, udpMapStats, latencyConfigMap, protoCfgMap}

	// DNS Parser maps
	// Those maps are only used within the DNS parser that is included in the dispatcher and we assume >=5.14
	DNSParserErrorMap = program.MapBuilder(dnsparser.ErrorMapName, IngressDispatcherProcessTree, IngressDispatcherProcessTreeTimer, EgressDispatcherProcessTree, EgressDispatcherProcessTreeTimer)
	DNSDomainMap      = program.MapBuilder(dnsparser.DomainToIDMapName, IngressDispatcherProcessTree, IngressDispatcherProcessTreeTimer, EgressDispatcherProcessTree, EgressDispatcherProcessTreeTimer)
	DNSDomainMapRev   = program.MapBuilder(dnsparser.IDToDomainMapName, IngressDispatcherProcessTree, IngressDispatcherProcessTreeTimer, EgressDispatcherProcessTree, EgressDispatcherProcessTreeTimer)
	DNSGlobalIDMap    = program.MapBuilder(dnsparser.GlobalDNSIDMapName, IngressDispatcherProcessTree, IngressDispatcherProcessTreeTimer, EgressDispatcherProcessTree, EgressDispatcherProcessTreeTimer)
	RequestIDMapName  = program.MapBuilder(dnsparser.RequestIDMapName, IngressDispatcherProcessTree, IngressDispatcherProcessTreeTimer, EgressDispatcherProcessTree, EgressDispatcherProcessTreeTimer)
	// This map is shared between the DNS parser and the process tree: the fdlookup and tcpsockops progs
	DNSIPToIDMaps        = program.MapUserFrom(ip.DNSIPToIDMaps)
	AllocationIDMap      = program.MapUserFrom(ip.AllocationIDMap)
	CgroupIDToAllocIDMap = program.MapUserFrom(ip.CgroupIDToAllocIDMap)
	// Layer3 configuration map, shared with many L3 programs
	protoCfgMap = program.MapUserFrom(base.CfgMap)

	// LPM maps
	Addr6LpmMap = program.MapUserFrom(base.Addr6LpmMap)
	Addr4LpmMap = program.MapUserFrom(base.Addr4LpmMap)

	// Dispatcher all maps
	dispatcherProcessTreeMaps = append(udpMaps,
		[]*program.Map{
			// Process Tree maps
			program.MapUserFrom(base.DestinationEndpointMap),
			program.MapUserFrom(base.ListenEndpointMap),
			program.MapUserFrom(base.ProcessTreeBinaryUUIDMap),
			program.MapUserFrom(base.BpfEndpointIdMap),
			program.MapUserFrom(base.EndpointIdMap),
			program.MapUserFrom(base.Addr6LpmMap),
			program.MapUserFrom(base.Addr4LpmMap),
		}...)
	dispatcherProcessTreeTimerMaps = append(dispatcherProcessTreeMaps, udpTimerMap)
	dispatcherMaps                 = udpMaps
)

func ProgsAndMaps(tcpTimestampEnable, cgroup, udpTimestampEnable bool) ([]*program.Program, []*program.Map) {
	ReportFunctionality()

	needDispatcher := false

	var progsInitSock, progsCollectStats []*program.Program
	var maps []*program.Map

	socktrackProgs, socktrackMaps := socktrack.EnableSocktrack()
	fdLookupProgs, fdLookupMaps := ip.Enable()
	maps = append(socktrackMaps, fdLookupMaps...)
	if !BaseLoaded {
		progsInitSock = append(socktrackProgs, fdLookupProgs...)
	}

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
			DNSDomainMap.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
			DNSDomainMapRev.SetMaxEntries(enterpriseOption.Config.ProcessTreeCacheSize)
			RequestIDMapName.SetMaxEntries(int(enterpriseOption.Config.BPFDNSParserMaxPendingRequests))

			maps = append(maps, DNSParserErrorMap)
			maps = append(maps, DNSIPToIDMaps)
			maps = append(maps, DNSDomainMap)
			maps = append(maps, DNSDomainMapRev)
			maps = append(maps, DNSGlobalIDMap)
			maps = append(maps, RequestIDMapName)
			maps = append(maps, AllocationIDMap)
			maps = append(maps, CgroupIDToAllocIDMap)
		}
	}

	if tcpEnabled || udpEnabled {
		maps = append(maps, Addr6LpmMap)
		maps = append(maps, Addr4LpmMap)
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
		if utils.CGroupSKBAvailable() {
			if !utils.SupportCGroupSKBProbeRead() {
				progsCollectStats = append(progsCollectStats, dispatcherNoProbeReadProgs...)
				maps = append(maps, dispatcherMaps...)
			} else if !utils.SupportProcessTree() {
				progsCollectStats = append(progsCollectStats, dispatcherProgs...)
				maps = append(maps, dispatcherMaps...)
			} else {
				var ourDispatcherProcessTreeProgs []*program.Program
				if !utils.SupportTimers() {
					ourDispatcherProcessTreeProgs = dispatcherProcessTreeProgs
					maps = append(maps, dispatcherProcessTreeMaps...)
				} else {
					ourDispatcherProcessTreeProgs = dispatcherProcessTreeTimerProgs
					maps = append(maps, dispatcherProcessTreeTimerMaps...)
				}
				for _, prog := range ourDispatcherProcessTreeProgs {
					prog.RewriteConstants[dnsparser.ParserEnabledName] = enterpriseOption.Config.EnableBPFDNSParser
					err := dnsparser.RewriteConstants(prog.RewriteConstants)
					if err != nil {
						// TODO: when we remove enabling layer3 from CRD, return this error and stop init of sensor
						logger.GetLogger().Error("Failed to rewrite DNS parser constants", logfields.Error, err)
					}
				}
				progsCollectStats = append(progsCollectStats, ourDispatcherProcessTreeProgs...)
			}
		} else {
			logger.GetLogger().Info("Cgroup support requires a later kernel (v5.4+ or RHEL equivalent)")
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
		err := l3.configureMaps(spec)
		if err != nil {
			logger.GetLogger().Warn("failed to configure layer3 maps", logfields.Error, err)
		}
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
	return utils.CGroupSKBAvailable()
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
		if tcpEnabled && spec.Parser.Tcp.RttHistogram.Enable && !utils.RTTHookAvailable() {
			return nil, fmt.Errorf("tcp rtt enabled in policy but kernel support missing")
		}
		if rawEnabled && !utils.RawHooksAvailable() {
			return nil, fmt.Errorf("raw sockets enabled in policy but kernel support missing")
		}
	}
	// However, disable cgroup and therefore DNS if the kernel is too old
	if !utils.CGroupSKBAvailable() {
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

func (l3 *l3Sensor) configureMaps(spec *v1alpha1.TracingPolicySpec) error {
	// If UDP is enabled then we need close events reported to maintain our maps.
	config := networkapi.Layer3ConfigValue{}
	layer3cfg.SetConfig(&config, rawEnabled, reportRawClose, udpEnabled)

	if tcpEnabled && (spec == nil || spec.Parser.Tcp != nil) {
		if err := tcp.SetConfig(&config); err != nil {
			return fmt.Errorf("failed to configure TCP maps: %w", err)
		}
		config.Proto.TCP4Enabled = 1
		config.Proto.TCP6Enabled = 1
	}
	if udpEnabled && (spec == nil || spec.Parser.Udp != nil) {
		if err := udp.SetConfig(&config); err != nil {
			return fmt.Errorf("failed to configure UDP maps: %w", err)
		}
		config.Proto.UDP4Enabled = 1
		config.Proto.UDP6Enabled = 1
	}
	if udpEnabled && enterpriseOption.Config.EnableBPFDNSParser && enterpriseOption.Config.EnableApplicationModel {
		err := dnsparser.PopulateDomainMapsWithLocalhost()
		if err != nil {
			return fmt.Errorf("failed to populate the DNS domains maps with localhost: %w", err)
		}

		ipToIDMapsFile := filepath.Join(bpf.MapPrefixPath(), dnsparser.IPToIDMapsName)
		ipToIDMapsRaw, err := ebpf.LoadPinnedMap(ipToIDMapsFile, nil)
		if err != nil {
			return fmt.Errorf("failed to load %q map: %w", ipToIDMapsFile, err)
		}
		// Not closing this map as it will be potentially used by the reconciler
		ipToIDMaps := dnsparser.NewIPToIDMaps(ipToIDMapsRaw)

		err = ipToIDMaps.CreatePreallocMaps()
		if err != nil {
			return fmt.Errorf("failed to initialize the DNS maps: %w", err)
		}

		err = ipToIDMaps.PopulatePreallocMapsWithLocalhost()
		if err != nil {
			return fmt.Errorf("failed to populate the DNS IP to ID maps with localhost: %w", err)
		}

		// Program the QuotasInitDNSDomainMappings
		var dnsDomainMap dnsparser.DomainMap
		defer dnsDomainMap.CloseMaps()
		for endpoint, id := range datapath.QuotasInitDNSDomainMappings {
			err := dnsDomainMap.Update(endpoint.Dns, id)
			if err != nil {
				return fmt.Errorf("failed to write BPF domain maps with endpoint %s and id %d: %w", endpoint, id, err)
			}
		}

		if enterpriseOption.Config.EnableBPFDNSPerPod {
			m := manager.Get().GetControllerManager().Manager
			reconciler, err := dnsparser.NewPodReconciler(m.GetClient(), &ipToIDMaps)
			if err != nil {
				return fmt.Errorf("failed to create a new Pod reconciler for the DNS parser per Pod feature: %w", err)
			}
			if err = reconciler.SetupWithManager(m); err != nil {
				return fmt.Errorf("failed to setup the Pod reconciler for the DNS parser per Pod feature: %w", err)
			}
		} else {
			// If the reconciler does not manage this map, let's
			// close the raw map as the wrapper will be GCed
			ipToIDMapsRaw.Close()
		}
	}
	if icmpEnabled && (spec == nil || spec.Parser.Icmp != nil) {
		icmp.SetConfig(&config)
		config.Proto.ICMP4Enabled = 1
		config.Proto.ICMP6Enabled = 1
	}
	// Rawsock has no config maps.

	err := layer3cfg.UpdateMap(config)
	if err != nil {
		return fmt.Errorf("failed to write the layer3 config: %w", err)
	}

	return nil
}

func (l3 *l3Sensor) configureSensor() error {
	if tcpEnabled {
		tcp.ConfigureSensor()
		logger.GetLogger().Debug("TCP Loader", "timestampEnabled", tcp.TimestampEnabled)
		if tcp.TimestampEnabled {
			if err := networklatency.ConfigureLatency(unix.IPPROTO_TCP, tcpconfig.LatencyConfig); err != nil {
				logger.GetLogger().Warn("ConfigureLatency TCP", logfields.Error, err)
				return err
			}
			networklatency.Start()
		}
	}
	if udpEnabled {
		udp.ConfigureSensor()
		logger.GetLogger().Debug("UDP Loader", "timestampEnabled", udp.TimestampEnabled)
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
		err := l3.configureMaps(nil)
		if err != nil {
			return fmt.Errorf("failed to configure layer3 maps: %w", err)
		}
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
			logger.GetLogger().Warn("CGRP", logfields.Error, err)
			return err
		}
	case "cgrp_egress":
		if cgrp_egress_configured {
			break
		}
		cgrp_egress_configured = true
		err := cgroup.LoadCgroupProgram(args.BPFDir, args.Load, args.Maps, args.Verbose)
		if err != nil {
			logger.GetLogger().Warn("CGRP", logfields.Error, err)
			return err
		}
	case "cgrp_inet4_bind", "cgrp_inet6_bind":
		err := cgroup.LoadCgroupProgram(args.BPFDir, args.Load, args.Maps, args.Verbose)
		if err != nil {
			logger.GetLogger().Warn("CGRP", logfields.Error, err)
			return err
		}
	case "tc_egress":
		err := networklatency.AttachTc(args)
		if err != nil {
			logger.GetLogger().Warn("TC_EGRESS", logfields.Error, err)
			return err
		}
	case "tcp_fentry", "udp_fentry", "icmp_fentry", "rawsock_fentry", "socktrack_fentry":
		err := program.LoadTracingProgram(args.BPFDir, args.Load, args.Maps, args.Verbose)
		if err != nil {
			logger.GetLogger().Warn("FENTRY", logfields.Error, err)
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
			logger.GetLogger().Warn("LAYER3_SENSOR", logfields.Error, err)
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
		logger.GetLogger().Error("TCP init failed. Disabling Layer3", logfields.Error, err)
		return
	}

	err = udp.Init()
	if err != nil {
		logger.GetLogger().Error("UDP init failed. Disabling Layer3", logfields.Error, err)
		return
	}

	err = icmp.Init()
	if err != nil {
		logger.GetLogger().Error("ICMP init failed. Disabling Layer3", logfields.Error, err)
		return
	}

	err = rawsock.Init()
	if err != nil {
		logger.GetLogger().Error("RAW init failed. Disabling Layer3", logfields.Error, err)
		return
	}

	l3 := &l3Sensor{
		name: "Layer3 sensor",
	}

	sensors.RegisterPolicyHandlerAtInit(l3.name, l3)

	sensors.RegisterProbeType("layer3_sensor", l3)
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
	if enterpriseOption.Config.EnableTCPRTT {
		if !utils.RTTHookAvailable() {
			return fmt.Errorf("tcp rtt enabled but kernel support missing")
		}
	}
	if enterpriseOption.Config.EnableUDP {
		udpEnabled = true
		if enterpriseOption.Config.UDPInKernelManaged && (!utils.SupportProcessTree() || !utils.SupportTimers()) {
			return fmt.Errorf("UDP in kernel management requires process tree and bpf timer support")
		}
	}
	if enterpriseOption.Config.EnableICMP {
		icmpEnabled = true
	}
	if enterpriseOption.Config.EnableRawsock {
		if !utils.RawHooksAvailable() {
			return fmt.Errorf("raw sockets enabled but kernel support missing")
		}
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

func RunLayer3Progs(ctx context.Context, sm *sensors.Manager) error {
	// By default, enable CGroup/SKB.
	progs, maps := ProgsAndMaps(enterpriseOption.Config.EnableLatency, udpCGroup, enterpriseOption.Config.EnableLatency)
	var mgr *sensors.Manager
	if sm != nil {
		mgr = sm
	} else {
		mgr = observer.GetSensorManager()
	}
	initialLayer3Sensor := &sensors.Sensor{
		Name:  api.BaseLayer3Policy,
		Progs: progs,
		Maps:  maps,
	}
	if err := mgr.AddSensor(ctx, initialLayer3Sensor.Name, initialLayer3Sensor); err != nil {
		return err
	}
	return mgr.EnableSensor(ctx, initialLayer3Sensor.Name)
}

func StartLayer3Progs(ctx context.Context, sm *sensors.Manager) error {
	BaseLoaded = false
	ReportFunctionality()
	err := EnableLayer3Progs()
	if err != nil {
		return err
	}
	err = RunLayer3Progs(ctx, sm)
	BaseLoaded = true
	if err != nil {
		return err
	}
	udp.StartIdleSocketGC()
	return nil
}

var reportFuncOnce sync.Once

func ReportFunctionality() {
	reportFuncOnce.Do(func() {
		logger.GetLogger().Info("Layer3 functionality", "values", utils.LogLayer3Features())
	})
}

func HTTPContext() *program.Map {
	return tcpconfig.HTTPContext
}

func SocketMap() *program.Map {
	return tcpconfig.SocketMap
}

func SocketStats() *program.Map {
	return tcpconfig.SocketMapStats
}

func TcpSocketMap() *program.Map {
	return tcpconfig.TcpSocketMap
}

func TcpSocketStats() *program.Map {
	return tcpconfig.TcpSocketStats
}

func TLSContext() *program.Map {
	return tcpconfig.TLSContext
}

func TLSMapStats() *program.Map {
	return tcpconfig.TLSMapStats
}

func TLSBottles() *program.Map {
	return tcpconfig.TLSBottles
}

func TLSBottleStats() *program.Map {
	return tcpconfig.TLSBottleStats
}
