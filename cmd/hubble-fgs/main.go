package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/bugtool"
	"github.com/isovalent/hubble-fgs/pkg/cilium"
	"github.com/isovalent/hubble-fgs/pkg/defaults"
	"github.com/isovalent/hubble-fgs/pkg/filters"
	fgsGrpc "github.com/isovalent/hubble-fgs/pkg/grpc"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/metrics"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/version"

	// Imported to allow sensors to be initialized inside init().
	_ "github.com/isovalent/hubble-fgs/pkg/sensors"

	"github.com/cilium/cilium/pkg/option"
	gops "github.com/google/gops/agent"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
	"gopkg.in/natefinch/lumberjack.v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func getExportFilters() ([]*fgs.Filter, []*fgs.Filter, error) {
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

func saveInitInfo() error {
	info := bugtool.InitInfo{
		ExportFname: exportFilename,
		LibDir:      observer.HubbleLib,
		BtfFname:    observer.ObserverBTF,
		MetricsAddr: metricsServer,
		ServerAddr:  serverAddress,
	}
	return bugtool.SaveInitInfo(&info)
}

func hubbleFGSExecute() error {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	logger.GetLogger().WithField("config", viper.AllSettings()).Info("config settings")
	readAndSetFlags()

	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.CheckOrMountCgroup2()

	bpf.ConfigureResourceLimits()
	observerDir := getObserverDir()
	kprobe := observer.NewObserverKprobe(
		observerDir,
		observerDir,
		ciliumBPF,
		networkInterfaces,
		configFile,
		debug,
		enableK8sAPI,
		exportTCPStatsSampleSeg,
	)
	if err := kprobe.InitObserverSync(); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())

	/* Remove any stale programs, otherwise feature set change can cause
	 * old programs to linger resulting in undefined behavior. And because
	 * we recapture current running state from proc and/or have cache of
	 * events no state should be lost/missed.
	 */
	kprobe.RemovePrograms()
	os.Mkdir(defaults.DefaultRunDir, os.ModeDir)
	go func() {
		<-sigs
		kprobe.PrintStats()
		kprobe.RemovePrograms()
		cancel()
		os.Exit(1)
	}()

	err := btf.InitCachedBTF(observer.HubbleLib, observer.ObserverBTF, ctx)
	if err != nil {
		return err
	}

	if runStandalone {
		return kprobe.StartStandalone(ctx)
	}

	if metricsServer != "" {
		go metrics.EnableMetrics(metricsServer)
	}

	watcher, err := getWatcher(enableK8sAPI)
	if err != nil {
		return err
	}
	ciliumState, err := cilium.GetCiliumState(enableCiliumAPI, ctx)
	if err != nil {
		return err
	}
	processManager, err := fgsGrpc.NewProcessManager(
		logger.GetLogger(),
		processCacheSize,
		watcher,
		ciliumState,
		enableProcessCred,
		enableCiliumAPI)
	if err != nil {
		return err
	}
	server := fgsGrpc.NewServer(processManager, kprobe.ObserverSync)
	if err = Serve(ctx, serverAddress, server); err != nil {
		return err
	}
	if exportFilename != "" {
		if err = startExporter(ctx, server); err != nil {
			return err
		}
	}

	logger.GetLogger().WithField("enabled", exportFilename != "").WithField("fileName", exportFilename).Info("Exporter configuration")
	kprobe.AddListener(processManager)
	saveInitInfo()
	return kprobe.Start(ctx)
}

// getObserverDir returns the path to the observer directory based on the BPF
// map root. This function relies on the map root to be set properly via
// github.com/isovalent/hubble-fgs/pkg/bpf.CheckOrMountFS().
func getObserverDir() string {
	const observerDir = "tcpmon"
	return filepath.Join(bpf.GetMapRoot(), observerDir)
}

func startExporter(ctx context.Context, server *fgsGrpc.Server) error {
	allowList, denyList, err := getExportFilters()
	if err != nil {
		return err
	}
	writer := lumberjack.Logger{
		Filename:   exportFilename,
		MaxSize:    exportFileMaxSizeMB,
		MaxBackups: exportFileMaxBackups,
		Compress:   exportFileCompress,
	}
	if exportFileRotationInterval != 0 {
		logger.GetLogger().WithField("duration", exportFileRotationInterval).Info("Periodically rotating JSON export files")
		go func() {
			ticker := time.NewTicker(exportFileRotationInterval)
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if rotationErr := writer.Rotate(); rotationErr != nil {
						logger.GetLogger().
							WithError(rotationErr).
							WithField("filename", exportFilename).
							Warn("Failed to rotate JSON export file")
					}
				}
			}
		}()
	}
	encoder := json.NewEncoder(&writer)
	var rateLimiter *fgsGrpc.RateLimiter
	if exportRateLimit >= 0 {
		rateLimiter = fgsGrpc.NewRateLimiter(ctx, 1*time.Minute, exportRateLimit, encoder)
	}
	var aggregationOptions *fgs.AggregationOptions
	if enableExportAggregation {
		aggregationOptions = &fgs.AggregationOptions{
			WindowSize:        durationpb.New(exportAggregationWindowSize),
			ChannelBufferSize: exportAggregationBufferSize,
		}
	}
	req := fgs.GetEventsRequest{AllowList: allowList, DenyList: denyList, AggregationOptions: aggregationOptions}
	logger.GetLogger().WithFields(logrus.Fields{"logger": writer, "request": req}).Info("Starting JSON exporter")
	exporter := fgsGrpc.NewExporter(ctx, &req, server, encoder, rateLimiter)
	go exporter.Start()
	return nil
}

func Serve(ctx context.Context, address string, server *fgsGrpc.Server) error {
	grpcServer := grpc.NewServer()
	fgs.RegisterFineGuidanceSensorsServer(grpcServer, server)
	go func(address string) {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			logger.GetLogger().WithError(err).WithField("address", address).Fatal("Failed to start gRPC server")
		}
		logger.GetLogger().WithField("address", address).Info("Starting gRPC server")
		if err = grpcServer.Serve(listener); err != nil {
			logger.GetLogger().WithError(err).Error("Failed to close gRPC server")
		}
	}(address)
	go func() {
		<-ctx.Done()
		grpcServer.Stop()
	}()
	return nil
}

func getWatcher(enableK8sAPI bool) (fgsGrpc.K8sResourceWatcher, error) {
	if enableK8sAPI {
		logger.GetLogger().Info("Enabling Kubernetes API")
		config, err := rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
		k8sClient := kubernetes.NewForConfigOrDie(config)
		return fgsGrpc.NewK8sWatcher(k8sClient, 60*time.Second), nil

	}
	logger.GetLogger().Info("Disabling Kubernetes API")
	return fgsGrpc.NewFakeK8sWatcher(nil), nil
}

func execute() error {
	rootCmd := &cobra.Command{
		Use:   "hubble-fgs SOURCE_DIR BUCKET",
		Short: "Hubble FGS",
		Run: func(cmd *cobra.Command, args []string) {
			logger.GetLogger().WithField("version", version.Version).Info("Starting hubble-fgs")
			if err := gops.Listen(gops.Options{}); err != nil {
				logger.GetLogger().WithError(err).Fatal("Failed to start gops")
			}
			if err := hubbleFGSExecute(); err != nil {
				logger.GetLogger().WithError(err).Fatal("Failed to start hubble-fgs")
			}
		},
	}

	cobra.OnInitialize(func() {
		viper.SetEnvPrefix("fgs")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".") // look for a config file in cwd first, useful during development
		if err := viper.ReadInConfig(); err == nil {
			logger.GetLogger().Info("Loaded config from file")
		}
		if viper.IsSet(keyConfigDir) {
			configDir := viper.GetString(keyConfigDir)
			cm, err := option.ReadDirConfig(configDir)
			if err != nil {
				logger.GetLogger().WithField(keyConfigDir, configDir).WithError(err).Fatal("Failed to read config from directory")
			}
			if err := viper.MergeConfigMap(cm); err != nil {
				logger.GetLogger().WithField(keyConfigDir, configDir).WithError(err).Fatal("Failed to merge config from directory")
			}
			logger.GetLogger().WithField(keyConfigDir, configDir).Info("Loaded config from directory")
		}
		viper.AutomaticEnv()
	})

	flags := rootCmd.PersistentFlags()

	flags.String(keyConfigDir, "", "Configuration directory that contains a file for each option")
	flags.BoolP(keyDebug, "d", false, "Enable debug messages")
	flags.String(keyHubbleLib, "/var/lib/hubble-fgs/", "Location of hubble libs (btf and bpf files)")
	flags.String(keyBTF, "", "Location of btf")

	flags.String(keyProcFS, "/proc/", "Location of procfs to consume existing PIDs")
	flags.String(keyKernelVersion, "", "Kernel version")
	flags.Int(keyVerbosity, 0, "set verbosity level")
	flags.Int(keyProcessCacheSize, 32768, "Size of the process cache")
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
	flags.String(keyMetricsServer, "", "Metrics server address (e.g. ':2112'). Set it to an empty string to disable.")
	flags.String(keyNetworkInterfaces, "", "Comma separated list of regex expressions to use to apply protocol parsers")
	flags.String(keyServerAddress, "localhost:54321", "gRPC server address")
	flags.String(keyCiliumBPF, "", "Cilium BPF directory")
	flags.Bool(keyEnableProcessCred, false, "Enable process_cred events")

	// Config files
	flags.String(keyConfigFile, "", "Configuration file to load from")

	// Options for debugging/development, not visible to users
	flags.Bool(keyRunStandalone, false, "Just start the observer and dump events to stdout")
	flags.MarkHidden(keyRunStandalone)

	flags.Bool(keyIgnoreMissingProgs, false, "Ignore missing BPF programs")
	flags.MarkHidden(keyIgnoreMissingProgs)

	// JSON export aggregation options.
	flags.Bool(keyEnableExportAggregation, false, "Enable JSON export aggregation")
	flags.Duration(keyExportAggregationWindowSize, 15*time.Second, "JSON export aggregation time window")
	flags.Uint64(keyExportAggregationBufferSize, 10000, "Aggregator channel buffer size")

	// JSON export filter options
	flags.String(keyExportAllowlist, "", "JSON export allowlist")
	flags.String(keyExportDenylist, "", "JSON export denylist")

	// TCP Statisticss options
	flags.Uint32(keyTCPStatsSampleSeg, 0, "TCP statistics sample seg rate")

	viper.BindPFlags(flags)
	return rootCmd.Execute()
}
