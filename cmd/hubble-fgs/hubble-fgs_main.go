package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/covalentio/hubble-fgs/api/v1/fgs"
	"github.com/covalentio/hubble-fgs/pkg/bpf"
	"github.com/covalentio/hubble-fgs/pkg/cilium"
	"github.com/covalentio/hubble-fgs/pkg/defaults"
	"github.com/covalentio/hubble-fgs/pkg/filters"
	fgsGrpc "github.com/covalentio/hubble-fgs/pkg/grpc"
	"github.com/covalentio/hubble-fgs/pkg/logger"
	"github.com/covalentio/hubble-fgs/pkg/metrics"
	"github.com/covalentio/hubble-fgs/pkg/observer"
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

	processCacheSize     int
	exportFilename       string
	exportFileMaxSizeMB  int
	exportFileMaxBackups int
	exportFileCompress   bool
	enableK8sAPI         bool
	metricsServer        string
	enableCiliumAPI      bool
	networkInterfaces    string
	serverAddress        string
	runStandalone        bool
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
	kprobe := observer.NewObserverKprobe(observerDir, observerDir,
		networkInterfaces,
		viper.GetBool("execve"),
		viper.GetBool("tls"), viper.GetBool("tlstc"),
		viper.GetBool("debug"))

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
	processManager, err := fgsGrpc.NewProcessManager(logger.GetLogger(), processCacheSize, watcher, ciliumState)
	if err != nil {
		return err
	}
	server := fgsGrpc.NewServer(processManager)
	if err = Serve(ctx, serverAddress, server); err != nil {
		return err
	}
	if exportFilename != "" {
		if err = startExporter(ctx, server); err != nil {
			return err
		}
	}
	kprobe.AddListener(processManager)
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
	logger.GetLogger().WithField("logger", writer).Info("Starting JSON exporter")
	encoder := json.NewEncoder(&writer)
	req := fgs.GetEventsRequest{AllowList: allowList, DenyList: denyList}
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
	flags.BoolP("execve", "e", false, "Enable execve events")
	flags.BoolP("tls", "t", false, "Enable tls events")
	flags.BoolP("tlstc", "", false, "Enable TLS TC events")
	flags.IntVar(&processCacheSize, "process-cache-size", 32768, "Size of the process cache")
	flags.StringVar(&exportFilename, "export-filename", "", "Filename for JSON export. Disabled by default")
	flags.IntVar(&exportFileMaxSizeMB, "export-file-max-size-mb", 10, "Size in MB for rotating JSON export files")
	flags.IntVar(&exportFileMaxBackups, "export-file-max-backups", 5, "Number of rotated JSON export files to retain")
	flags.BoolVar(&exportFileCompress, "export-file-compress", true, "Compress rotated JSON export files")
	flags.String("log-level", "info", "Set log level")
	flags.BoolVar(&enableK8sAPI, "enable-k8s-api", false, "Access Kubernetes API to associate FGS events with Kubernetes pods")
	flags.StringVar(&metricsServer, "metrics-server", "", "Metrics server address (e.g. ':2112'). Set it to an empty string to disable.")
	flags.BoolVar(&enableCiliumAPI, "enable-cilium-api", false, "Access Cilium API to associate FGS events with Cilium endpoints and DNS cache")
	flags.StringVar(&networkInterfaces, "network-interfaces", "", "Comma separated list of regex expressions to use to apply protocol parsers")
	flags.StringVar(&serverAddress, "server-address", "localhost:54321", "gRPC server address")
	viper.BindPFlags(flags)

	// Options for debugging/development, not visible to users
	flags.BoolVar(&runStandalone, "run-standalone", false, "Just start the observer and dump events to stdout")
	flags.MarkHidden("run-standalone")

	flags.BoolVarP(&observer.IgnoreMissingProgs, "ignore-missing-progs", "", false, "Ignore missing BPF programs")
	flags.MarkHidden("ignore-missing-progs")

}

func hubbleFGSMain() {
	cmd.Execute()
}
