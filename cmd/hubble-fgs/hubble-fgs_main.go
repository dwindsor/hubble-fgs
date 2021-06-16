package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang/protobuf/ptypes"
	gops "github.com/google/gops/agent"
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
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"gopkg.in/natefinch/lumberjack.v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	observerDir = "/sys/fs/bpf/tcpmon/"

	cmd *cobra.Command

	processCacheSize           int
	exportFilename             string
	exportFileMaxSizeMB        int
	exportFileRotationInterval time.Duration
	exportFileMaxBackups       int
	exportFileCompress         bool
	enableK8sAPI               bool
	metricsServer              string
	enableCiliumAPI            bool
	networkInterfaces          string
	serverAddress              string
	runStandalone              bool
	ciliumBPF                  string
	enableProcessCred          bool
	configFile                 string
	enableCRD                  bool

	// Export aggregation options
	enableExportAggregation     bool
	exportAggregationWindowSize time.Duration
	exportAggregationBufferSize uint64
)

func getExportFilters() ([]*fgs.Filter, []*fgs.Filter, error) {
	allowList, err := filters.ParseFilterList(os.Getenv("EXPORT_ALLOW_LIST"))
	if err != nil {
		return nil, nil, err
	}
	denyList, err := filters.ParseFilterList(os.Getenv("EXPORT_DENY_LIST"))
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
	tls := viper.GetBool("tls")

	ctx, cancel := context.WithCancel(context.Background())
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	if tls {
		bpf.CheckOrMountCgroup2()
	}
	bpf.ConfigureResourceLimits()
	kprobe := observer.NewObserverKprobe(observerDir, observerDir, ciliumBPF,
		networkInterfaces, configFile, []observer.GenericTracepointConf{},
		viper.GetBool("tls"), viper.GetBool("tlstc"),
		viper.GetBool("debug"), viper.GetBool("enable-crd"))

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

	err := btf.ConfigureBTF(observer.HubbleLib, ctx)
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
		logger.GetLogger(), processCacheSize, watcher, ciliumState, enableProcessCred, enableCiliumAPI)
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
	kprobe.AddListener(processManager)
	saveInitInfo()
	return kprobe.Start(ctx)
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
	var aggregationOptions *fgs.AggregationOptions
	if enableExportAggregation {
		aggregationOptions = &fgs.AggregationOptions{
			WindowSize:        ptypes.DurationProto(exportAggregationWindowSize),
			ChannelBufferSize: exportAggregationBufferSize,
		}
	}
	req := fgs.GetEventsRequest{AllowList: allowList, DenyList: denyList, AggregationOptions: aggregationOptions}
	logger.GetLogger().WithFields(logrus.Fields{"logger": writer, "request": req}).Info("Starting JSON exporter")
	exporter := fgsGrpc.NewExporter(ctx, &req, server, encoder)
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

func init() {
	cmd = &cobra.Command{
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

	flags := cmd.PersistentFlags()

	flags.BoolP("debug", "d", false, "Enable debug messages")
	flags.StringVar(&observer.HubbleLib, "hubble-lib", "/var/lib/hubble-fgs/", "Location of hubble libs (btf and bpf files)")
	flags.StringVar(&observer.ObserverBTF, "btf", "", "Location of btf")

	flags.StringVar(&observer.ProcFS,
		"procfs", "/proc/", "Location of procfs to consume existing PIDs")
	flags.StringVar(&observer.KernelVersion, "kernel", "", "Kernel version")
	flags.IntVar(&observer.Verbosity, "verbose", 0, "set verbosity level")
	flags.BoolP("tls", "t", false, "Enable tls events")
	flags.BoolP("tlstc", "", false, "Enable TLS TC events")
	flags.IntVar(&processCacheSize, "process-cache-size", 32768, "Size of the process cache")
	flags.StringVar(&exportFilename, "export-filename", "", "Filename for JSON export. Disabled by default")
	flags.IntVar(&exportFileMaxSizeMB, "export-file-max-size-mb", 10, "Size in MB for rotating JSON export files")
	flags.DurationVar(&exportFileRotationInterval, "export-file-rotation-interval", 0,
		"Interval at which to rotate JSON export files in addition to rotating them by size")
	flags.IntVar(&exportFileMaxBackups, "export-file-max-backups", 5, "Number of rotated JSON export files to retain")
	flags.BoolVar(&exportFileCompress, "export-file-compress", false, "Compress rotated JSON export files")
	flags.String("log-level", "info", "Set log level")
	flags.String("log-format", "text", "Set log format")
	flags.BoolVar(&enableK8sAPI, "enable-k8s-api", false, "Access Kubernetes API to associate FGS events with Kubernetes pods")
	flags.BoolVar(&enableCRD, "enable-crd", false, "Enables K8s CRD watchers")
	flags.StringVar(&metricsServer, "metrics-server", "", "Metrics server address (e.g. ':2112'). Set it to an empty string to disable.")
	flags.BoolVar(&enableCiliumAPI, "enable-cilium-api", false, "Access Cilium API to associate FGS events with Cilium endpoints and DNS cache")
	flags.StringVar(&networkInterfaces, "network-interfaces", "", "Comma separated list of regex expressions to use to apply protocol parsers")
	flags.StringVar(&serverAddress, "server-address", "localhost:54321", "gRPC server address")
	flags.StringVar(&ciliumBPF, "cilium-bpf", "", "Cilium BPF directory")
	flags.BoolVar(&enableProcessCred, "enable-process-cred", false, "Enable process_cred events")
	viper.BindPFlags(flags)

	// Config files
	flags.StringVar(&configFile, "config-file", "", "Configuration file to load from")

	// Options for debugging/development, not visible to users
	flags.BoolVar(&runStandalone, "run-standalone", false, "Just start the observer and dump events to stdout")
	flags.MarkHidden("run-standalone")

	flags.BoolVarP(&observer.IgnoreMissingProgs, "ignore-missing-progs", "", false, "Ignore missing BPF programs")
	flags.MarkHidden("ignore-missing-progs")

	// JSON export aggregation options.
	flags.BoolVar(&enableExportAggregation, "enable-export-aggregation", false, "Enable JSON export aggregation")
	flags.DurationVar(&exportAggregationWindowSize, "export-aggregation-window-size", 15*time.Second, "JSON export aggregation time window")
	flags.Uint64Var(&exportAggregationBufferSize, "export-aggregation-buffer-size", 10000, "Aggregator channel buffer size")
}

func hubbleFGSMain() {
	cmd.Execute()
}
