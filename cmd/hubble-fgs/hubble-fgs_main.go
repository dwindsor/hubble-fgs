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
	"github.com/covalentio/hubble-fgs/pkg/grpc"
	"github.com/covalentio/hubble-fgs/pkg/logger"
	"github.com/covalentio/hubble-fgs/pkg/metrics"
	"github.com/covalentio/hubble-fgs/pkg/observer"
	"github.com/covalentio/hubble-fgs/pkg/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

	err := os.Remove(defaults.GetSocketPath())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	os.Mkdir(defaults.DefaultRunDir, os.ModeDir)
	s, err := net.Listen("unix", defaults.GetSocketPath())
	if err != nil {
		return err
	}
	go func() {
		<-sigs
		kprobe.PrintStats()
		kprobe.RemovePrograms()
		cancel()
		if err = s.Close(); err != nil {
			logger.GetLogger().WithError(err).Warn("Failed to close socket")
		}
		os.Exit(1)
	}()

	go server.ServeEvents(kprobe, ctx, s)
	if metricsServer != "" {
		go metrics.EnableMetrics(metricsServer)
	}

	if exportFilename != "" {
		encoder := json.NewEncoder(&lumberjack.Logger{
			Filename:   exportFilename,
			MaxSize:    exportFileMaxSizeMB,
			MaxBackups: exportFileMaxBackups,
			Compress:   exportFileCompress,
		})
		watcher, err := getWatcher(enableK8sAPI)
		if err != nil {
			return err
		}
		ciliumState, err := cilium.GetCiliumState(enableCiliumAPI, ctx)
		if err != nil {
			return err
		}
		allowList, denyList, err := getExportFilters()
		if err != nil {
			return err
		}
		processManager, err := grpc.NewProcessManager(logger.GetLogger(), encoder, processCacheSize, watcher, ciliumState, allowList, denyList)
		if err != nil {
			return err
		}
		kprobe.AddListener(processManager)
	}
	return kprobe.Start(ctx)
}

func getWatcher(enableK8sAPI bool) (grpc.K8sResourceWatcher, error) {
	if enableK8sAPI {
		logger.GetLogger().Info("Enabling Kubernetes API")
		config, err := rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
		k8sClient := kubernetes.NewForConfigOrDie(config)
		return grpc.NewK8sWatcher(k8sClient, 60*time.Second), nil

	}
	logger.GetLogger().Info("Disabling Kubernetes API")
	return grpc.NewFakeK8sWatcher(nil), nil
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
	flags.BoolVarP(&observer.SetPidMax, "set-pid-max", "", false, "Configures pid_max procFS requirements on startup")
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
	viper.BindPFlags(flags)
}

func hubbleFGSMain() {
	cmd.Execute()
}
