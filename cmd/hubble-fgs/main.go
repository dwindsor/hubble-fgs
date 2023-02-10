package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	// This needs to be first to be first in order to force oss consts to be fixed up
	"github.com/cilium/tetragon/pkg/config"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	_ "github.com/isovalent/hubble-fgs/pkg/metrics/fixuposs"
	"github.com/isovalent/hubble-fgs/pkg/nscache"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/bugtool"
	"github.com/cilium/tetragon/pkg/cilium"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/exporter"
	"github.com/cilium/tetragon/pkg/filters"
	fgsGrpc "github.com/cilium/tetragon/pkg/grpc"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/ratelimit"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/server"
	"github.com/cilium/tetragon/pkg/version"
	"github.com/cilium/tetragon/pkg/watcher"
	"github.com/cilium/tetragon/pkg/watcher/crd"

	// Imported to allow sensors to be initialized inside init().
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/file"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"

	// Add enterprise-specific filters to the global registry
	_ "github.com/isovalent/hubble-fgs/pkg/filters"

	"github.com/cilium/lumberjack/v2"
	gops "github.com/google/gops/agent"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	log = logger.GetLogger()
)

func getExportFilters() ([]*tetragon.Filter, []*tetragon.Filter, error) {
	allowList, err := filters.ParseFilterList(viper.GetString(keyExportAllowlist))
	if err != nil {
		return nil, nil, err
	}
	denyList, err := filters.ParseFilterList(viper.GetString(keyExportDenylist))
	if err != nil {
		return nil, nil, err
	}
	return allowList, denyList, nil
}

func getFieldFilters() ([]*tetragon.FieldFilter, error) {
	fieldFilters := viper.GetString(keyFieldFilters)

	filters, err := filters.ParseFieldFilterList(fieldFilters)
	if err != nil {
		return nil, err
	}

	return filters, nil
}

func saveInitInfo() error {
	info := bugtool.InitInfo{
		ExportFname: exportFilename,
		LibDir:      option.Config.HubbleLib,
		BtfFname:    option.Config.BTF,
		MetricsAddr: metricsServer,
		ServerAddr:  serverAddress,
	}
	return bugtool.SaveInitInfo(&info)
}

func readConfig(file string) (*config.GenericTracingConf, error) {
	if file == "" {
		return nil, nil
	}

	yamlData, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read yaml file %s: %w", configFile, err)
	}
	cnf, err := config.ReadConfigYaml(string(yamlData))
	if err != nil {
		return nil, err
	}

	return cnf, nil
}

func hubbleFGSExecute() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Logging should always be bootstrapped first. Do not add any code above this!
	if err := logger.SetupLogging(option.Config.LogOpts, option.Config.Debug); err != nil {
		log.Fatal(err)
	}

	log.WithField("version", version.Version).Info("Starting hubble-fgs")
	log.WithField("config", viper.AllSettings()).Info("config settings")

	if viper.IsSet(keyNetnsDir) {
		defaults.NetnsDir = viper.GetString(keyNetnsDir)
	}

	// Setup file system mounts
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.CheckOrMountCgroup2()

	// Raise memory resource
	bpf.ConfigureResourceLimits()

	// Get observer bpf maps and programs directory
	observerDir := getObserverDir()
	option.Config.BpfDir = observerDir
	option.Config.MapDir = observerDir

	// Check if option to remove old BPF and maps is enabled.
	if option.Config.ReleasePinned {
		err := os.RemoveAll(observerDir)
		if err != nil {
			log.WithField("bpf-dir", observerDir).WithError(err).Warn("Failed to release pinned BPF programs and map, Consider removing it manually")
		} else {
			log.WithField("bpf-dir", observerDir).Info("Successfully released pinned BPF programs and maps")
		}
	}

	// Get observer from configFile
	obs := observer.NewObserver(configFile)
	defer func() {
		file.TerminateFsScanner()
		obs.PrintStats()
		obs.RemovePrograms()
	}()

	go func() {
		// if we receive a signal, call cancel so that contexts are finalized, which will
		// leads to normally return from hubbleFGSExecute().
		s := <-sigs
		log.Infof("Received signal %s, shutting down...", s)
		cancel()
	}()

	if err := obs.InitSensorManager(); err != nil {
		return fmt.Errorf("failed to start sensor manager: %w", err)
	}

	observer.SensorManager.LogSensorsAndProbes(ctx)

	// Remove old tcpmon BPF directory
	//
	// commit https://github.com/cilium/tetragon/commit/f1a37fc2dfbf5827611ad5b9db966502ecdb0db9
	// in OSS, changed the prefix where the bpf maps and programs should be pinned from "tcpmon"
	// to "tetragon".
	// commit https://github.com/isovalent/hubble-fgs/commit/642115d3b8d2283f4463bbc2208f4a959e93ba24
	// imported that change in v1.9.0-rc3.
	// Users upgrading from older (e.g., v1.8 versions) might end up with duplicated maps and
	// programs. We have no upgrade method, so completely remove the directory.
	oldBpfDir := filepath.Join(bpf.GetMapRoot(), "tcpmon")
	if err := os.RemoveAll(oldBpfDir); err != nil {
		log.Warnf("faied to clean %s. Consider removing it manually", oldBpfDir)
	}

	/* Remove any stale programs, otherwise feature set change can cause
	 * old programs to linger resulting in undefined behavior. And because
	 * we recapture current running state from proc and/or have cache of
	 * events no state should be lost/missed.
	 */
	obs.RemovePrograms()
	os.Mkdir(defaults.DefaultRunDir, os.ModeDir)

	err := btf.InitCachedBTF(ctx, option.Config.HubbleLib, option.Config.BTF)
	if err != nil {
		return fmt.Errorf("failed to init cached BTF: %w", err)
	}

	if err := observer.InitDataCache(dataCacheSize); err != nil {
		return err
	}

	if metricsServer != "" {
		go metrics.EnableMetrics(metricsServer)
	}

	watcher, err := getWatcher(option.Config.EnableK8s)
	if err != nil {
		return fmt.Errorf("failed to get k8s API watcher: %w", err)
	}
	ciliumState, err := cilium.InitCiliumState(ctx, option.Config.EnableCilium)
	if err != nil {
		return fmt.Errorf("failed to init cilium state: %w", err)
	}

	if err := process.InitCache(ctx, watcher, option.Config.EnableCilium, processCacheSize); err != nil {
		return fmt.Errorf("failed to init process cache: %w", err)
	}

	// cleanupWg is needed to ensure that gRPC code cleanly finishes before we exit (e.g,
	// due to a signal). This is needed, for example, so that the exported writes full
	// (uncorrupted) to the file. See: 4b7c8d1c427a46b864763e910e8f3511e1c4eb00.
	var cleanupWg sync.WaitGroup
	defer cleanupWg.Wait()

	// The "defer cleanupWg.Wait()" above, might introduce deadlocks if an error happens.
	// This is because cancel() will not be called until cleanupWg.Wait() returns.
	// But, the code in server/server.go:GetEventsWG() will only call cleanupWg.Done() if ctx.Done()
	// Which causes a deadlock. To fix this, we add a new ctx and we pass that to the rest of the
	// initialization functions. This means that we can cancel them without causing a deadlock
	// using cancel2.
	ctx, cancel2 := context.WithCancel(ctx)
	defer cancel2()

	pm, err := fgsGrpc.NewProcessManager(
		ctx,
		&cleanupWg,
		ciliumState,
		observer.SensorManager)
	if err != nil {
		return fmt.Errorf("failed to create process manager: %w", err)
	}
	if err = Serve(ctx, serverAddress, pm.Server); err != nil {
		return fmt.Errorf("failed to start gRPC server: %w", err)
	}
	if exportFilename != "" {
		if err = startExporter(ctx, pm.Server); err != nil {
			return fmt.Errorf("failed to start json exporter: %w", err)
		}
	}

	log.WithField("enabled", exportFilename != "").WithField("fileName", exportFilename).Info("Exporter configuration")
	obs.AddListener(pm)
	saveInitInfo()
	if option.Config.EnableK8s {
		go crd.WatchTracePolicy(ctx, observer.SensorManager)
	}

	logPinnedBpf(observerDir)

	// Load default base sensors
	if err := base.LoadDefault(ctx, observerDir, observerDir, option.Config.CiliumDir); err != nil {
		return err
	}

	if len(configFile) > 0 {
		var sens *sensors.Sensor
		cnf, err := readConfig(configFile)
		if err != nil {
			return fmt.Errorf("failed to read config: %w", err)
		}
		sens, err = sensors.GetMergedSensorFromParserPolicy(cnf.Name(), &cnf.Spec)
		if err != nil {
			return fmt.Errorf("failed to get sensors from parser policy: %w", err)
		}

		if err := sens.Load(ctx, observerDir, observerDir, option.Config.CiliumDir); err != nil {
			return err
		}

	}

	// Periodically log status
	go logStatus(ctx, obs)

	return obs.Start(ctx)
}

func logPinnedBpf(observerDir string) {
	finfo, err := os.Stat(observerDir)
	if err != nil {
		log.WithField("bpf-dir", observerDir).Info("Starting with empty BPF resources")
		return
	}

	if finfo.IsDir() == false {
		err := fmt.Errorf("is not a directory")
		log.WithField("bpf-dir", observerDir).WithError(err).Warn("Checking pinned BPF resources failed")
		// Do not fail, let bpf part handle it
		return
	}

	bpfRes, _ := os.ReadDir(observerDir)
	if len(bpfRes) == 0 {
		log.WithField("bpf-dir", observerDir).Info("Starting with empty BPF resources")
	} else {
		res := make([]string, 0)
		for _, b := range bpfRes {
			res = append(res, b.Name())
		}
		log.WithFields(logrus.Fields{
			"bpf-dir":    observerDir,
			"pinned-bpf": fmt.Sprintf("[%s]", strings.Join(res, " ")),
		}).Info("Starting with pinned BPF resources")
	}
}

// Periodically log current status every 1 hour. For lost or error
// events we ratelimit statistics to 1 message per every 5mins to
// continuously infor users that events are being lost without
// polluting logs.
func logStatus(ctx context.Context, obs *observer.Observer) {
	prevLost := uint64(0)
	prevErrors := uint64(0)
	lostTicker := time.NewTicker(5 * time.Minute)
	defer lostTicker.Stop()
	logTicker := time.NewTicker(1 * time.Hour)
	defer logTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-logTicker.C:
			// We always print stats
			obs.PrintStats()
			// Update lost and errors, to not print two consecutive lines at same time
			prevLost = obs.ReadLostEvents()
			prevErrors = obs.ReadErrorEvents()
		case <-lostTicker.C:
			lost := obs.ReadLostEvents()
			errors := obs.ReadErrorEvents()
			if lost > prevLost || errors > prevErrors {
				obs.PrintStats()
				prevLost = lost
				prevErrors = errors
			}
		}
	}
}

// getObserverDir returns the path to the observer directory based on the BPF
// map root. This function relies on the map root to be set properly via
// github.com/cilium/tetragon/pkg/bpf.CheckOrMountFS().
func getObserverDir() string {
	return bpf.MapPrefixPath()
}

func startExporter(ctx context.Context, server *server.Server) error {
	allowList, denyList, err := getExportFilters()
	if err != nil {
		return err
	}
	fieldFilters, err := getFieldFilters()
	if err != nil {
		return err
	}
	writer := &lumberjack.Logger{
		Filename:   exportFilename,
		MaxSize:    exportFileMaxSizeMB,
		MaxBackups: exportFileMaxBackups,
		Compress:   exportFileCompress,
	}

	// For non k8s deployments we explicitly want log files
	// with permission 0600
	if !option.Config.EnableK8s {
		writer.FileMode = os.FileMode(0600)
	}

	finfo, err := os.Stat(filepath.Clean(exportFilename))
	if err == nil && finfo.IsDir() {
		// Error if exportFilename points to a directory
		return fmt.Errorf("passed export JSON logs file point to a directory")
	}
	logFile := filepath.Base(exportFilename)
	logsDir, err := filepath.Abs(filepath.Dir(filepath.Clean(exportFilename)))
	if err != nil {
		log.WithError(err).Warnf("Failed to get absolute path of exported JSON logs '%s'", exportFilename)
		// Do not fail; we let lumberjack handle this. We want to
		// log the rotate logs operation.
		logsDir = filepath.Dir(exportFilename)
	}

	if exportFileRotationInterval < 0 {
		// Passed an invalid interval let's error out
		return fmt.Errorf("frequency '%s' at which to rotate JSON export files is negative", exportFileRotationInterval.String())
	} else if exportFileRotationInterval > 0 {
		log.WithFields(logrus.Fields{
			"directory": logsDir,
			"frequency": exportFileRotationInterval.String(),
		}).Info("Periodically rotating JSON export files")
		go func() {
			ticker := time.NewTicker(exportFileRotationInterval)
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					log.WithFields(logrus.Fields{
						"file":      logFile,
						"directory": logsDir,
					}).Info("Rotating JSON logs export")
					if rotationErr := writer.Rotate(); rotationErr != nil {
						log.WithError(rotationErr).
							WithField("file", exportFilename).
							Warn("Failed to rotate JSON export file")
					}
				}
			}
		}()
	}

	encoder := json.NewEncoder(writer)
	var rateLimiter *ratelimit.RateLimiter
	if exportRateLimit >= 0 {
		rateLimiter = ratelimit.NewRateLimiter(ctx, 1*time.Minute, exportRateLimit, encoder)
	}
	var aggregationOptions *tetragon.AggregationOptions
	if enableExportAggregation {
		aggregationOptions = &tetragon.AggregationOptions{
			WindowSize:        durationpb.New(exportAggregationWindowSize),
			ChannelBufferSize: exportAggregationBufferSize,
		}
	}
	req := tetragon.GetEventsRequest{AllowList: allowList, DenyList: denyList, AggregationOptions: aggregationOptions, FieldFilters: fieldFilters}
	log.WithFields(logrus.Fields{"fieldFilters": fieldFilters}).Debug("Configured field filters")
	log.WithFields(logrus.Fields{"logger": writer, "request": &req}).Info("Starting JSON exporter")
	exporter := exporter.NewExporter(ctx, &req, server, encoder, writer, rateLimiter)
	exporter.Start()
	return nil
}

func Serve(ctx context.Context, address string, server *server.Server) error {
	grpcServer := grpc.NewServer()
	tetragon.RegisterFineGuidanceSensorsServer(grpcServer, server)
	go func(address string) {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			log.WithError(err).WithField("address", address).Fatal("Failed to start gRPC server")
		}
		log.WithField("address", address).Info("Starting gRPC server")
		if err = grpcServer.Serve(listener); err != nil {
			log.WithError(err).Error("Failed to close gRPC server")
		}
	}(address)
	go func() {
		<-ctx.Done()
		grpcServer.Stop()
	}()
	return nil
}

func getWatcher(enableK8sAPI bool) (watcher.K8sResourceWatcher, error) {
	if enableK8sAPI {
		log.Info("Enabling Kubernetes API")
		config, err := rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
		k8sClient := kubernetes.NewForConfigOrDie(config)
		return watcher.NewK8sWatcher(k8sClient, 60*time.Second), nil

	}
	log.Info("Disabling Kubernetes API")
	return watcher.NewFakeK8sWatcher(nil), nil
}

func startGopsServer() error {
	// Empty means no gops
	if option.Config.GopsAddr == "" {
		return nil
	}

	if err := gops.Listen(gops.Options{
		Addr:                   option.Config.GopsAddr,
		ReuseSocketAddrAndPort: true,
	}); err != nil {
		return err
	}

	log.WithField("addr", option.Config.GopsAddr).Info("Starting gops server")

	return nil
}

func resizeCaches() error {
	if err := dns.ResizeCache(enterpriseOption.Config.DnsCacheSize); err != nil {
		return err
	}
	if err := nscache.ResizeCache(enterpriseOption.Config.NetNsCacheSize); err != nil {
		return err
	}
	return nil
}

func execute() error {
	rootCmd := &cobra.Command{
		Use:   "hubble-fgs",
		Short: "Run the Hubble FGS agent",
		Run: func(cmd *cobra.Command, args []string) {
			readAndSetFlags()

			// Unfortunately, due to an over-reliance on init() throughout the codebase,
			// we have to rely on resizing the caches here rather than simply initializing
			// them. (Otherwise we'd require a bunch of refactors and NewCache calls in
			// a lot of different places.) This should be fine to do as the operation
			// shouldn't be prohibitively expensive and the caches won't actually have any
			// entries yet.
			if err := resizeCaches(); err != nil {
				log.WithError(err).Fatal("Failed to configure caches")
			}

			if err := startGopsServer(); err != nil {
				log.WithError(err).Fatal("Failed to start gops")
			}

			if err := hubbleFGSExecute(); err != nil {
				log.WithError(err).Fatal("Failed to start hubble-fgs")
			}
		},
	}

	cobra.OnInitialize(func() {
		readConfigSettings(adminFgsConfDir, adminFgsConfDropIn, packageFgsConfDropIns)
	})

	flags := rootCmd.PersistentFlags()

	flags.String(keyConfigDir, "", "Configuration directory that contains a file for each option")
	flags.BoolP(keyDebug, "d", false, "Enable debug messages. Equivalent to '--log-level=debug'")
	flags.String(keyHubbleLib, "/var/lib/hubble-fgs/", "Location of hubble libs (btf and bpf files)")
	flags.String(keyBTF, "", "Location of btf")

	flags.String(keyProcFS, "/proc/", "Location of procfs to consume existing PIDs")
	flags.String(keyKernelVersion, "", "Kernel version")
	flags.Int(keyVerbosity, 0, "set verbosity level")
	flags.Int(keyProcessCacheSize, 65536, "Size of the process cache")
	flags.Int(keyDataCacheSize, 1024, "Size of the data events cache")
	flags.Bool(keyForceSmallProgs, false, "Force loading small programs, even in kernels with >= 5.3 versions")
	flags.String(keyExportFilename, "", "Filename for JSON export. Disabled by default")
	flags.Int(keyExportFileMaxSizeMB, 10, "Size in MB for rotating JSON export files")
	flags.Duration(keyExportFileRotationInterval, 0, "Interval at which to rotate JSON export files in addition to rotating them by size")
	flags.Int(keyExportFileMaxBackups, 5, "Number of rotated JSON export files to retain")
	flags.Bool(keyExportFileCompress, false, "Compress rotated JSON export files")
	flags.Int(keyExportRateLimit, -1, "Rate limit (per minute) for event export. Set to -1 to disable")
	flags.String(keyLogLevel, "info", "Set log level")
	flags.String(keyLogFormat, "text", "Set log format")
	flags.Bool(keyEnableK8sAPI, false, "Access Kubernetes API to associate FGS events with Kubernetes pods")
	flags.Bool(keyEnableCiliumAPI, false, "Access Cilium API to associate FGS events with Cilium endpoints and DNS cache")
	flags.Bool(keyEnableProcessAncestors, true, "Include ancestors in process exec events")
	flags.String(keyMetricsServer, "", "Metrics server address (e.g. ':2112'). Disabled by default")
	flags.String(keyServerAddress, "localhost:54321", "gRPC server address")
	flags.String(keyGopsAddr, "", "gops server address (e.g. 'localhost:8118'). Disabled by default")
	flags.String(keyCiliumBPF, "", "Cilium BPF directory")
	flags.Bool(keyEnableProcessCred, false, "Enable process_cred events")
	flags.Bool(keyEnableProcessNs, false, "Enable namespace information in process_exec and process_kprobe events")
	flags.Uint(keyEventQueueSize, 10000, "Set the size of the internal event queue.")
	flags.String(keyProtocolShift, "auto", "Shfit the socket protocol field (true) or not (false), or discover automatically (auto)")
	flags.Int(keyDnsCacheSize, 1024, "Set the size of the internal DNS cache. Higher values enable Tetragon to keep track of more destination names before evicting old ones")
	flags.Int(keyNetNsCacheSize, 256, "Set the size of the internal network namespace cache. This should be aligned with the maximum number of network namespaces (approximately, the maxumum number of pods) we expect to see in the system")

	// Config files
	flags.String(keyConfigFile, "", "Location of the TracingPolicy file")

	// JSON export aggregation options.
	flags.Bool(keyEnableExportAggregation, false, "Enable JSON export aggregation")
	flags.Duration(keyExportAggregationWindowSize, 15*time.Second, "JSON export aggregation time window")
	flags.Uint64(keyExportAggregationBufferSize, 10000, "Aggregator channel buffer size")

	// JSON export filter options
	flags.String(keyExportAllowlist, "", "JSON export allowlist")
	flags.String(keyExportDenylist, "", "JSON export denylist")

	// Field filters options for export
	flags.String(keyFieldFilters, "", "Field filters for event exports")

	// Network namespace options
	flags.String(keyNetnsDir, "/var/run/docker/netns/", "Network namespace dir")

	// Provide option to remove existing pinned BPF programs and maps in Tetragon's
	// observer dir on startup. Useful for doing upgrades/downgrades. Set to false to
	// disable.
	flags.Bool(keyReleasePinnedBPF, true, "Release all pinned BPF programs and maps in Tetragon BPF directory. Enabled by default. Set to false to disable")

	viper.BindPFlags(flags)
	return rootCmd.Execute()
}
