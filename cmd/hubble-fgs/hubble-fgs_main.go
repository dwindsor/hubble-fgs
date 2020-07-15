package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/covalentio/hubble-fgs/pkg/bpf"
	"github.com/covalentio/hubble-fgs/pkg/defaults"
	"github.com/covalentio/hubble-fgs/pkg/grpc"
	"github.com/covalentio/hubble-fgs/pkg/logger"
	"github.com/covalentio/hubble-fgs/pkg/observer"
	"github.com/covalentio/hubble-fgs/pkg/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/natefinch/lumberjack.v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	observerDir     = "/sys/fs/bpf/tcpmon/"
	varLibHubbleFGS = "/var/lib/hubble-fgs/"

	cmd *cobra.Command

	processCacheSize     int
	exportFilename       string
	exportFileMaxSizeMB  int
	exportFileMaxBackups int
	exportFileCompress   bool
	enableK8sAPI         bool
)

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
	kprobe := observer.NewObserverKprobe(observerDir, observerDir, viper.GetBool("execve"), viper.GetBool("tls"), viper.GetBool("debug"))

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
		processManager, err := grpc.NewProcessManager(logger.GetLogger(), encoder, processCacheSize, watcher)
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
	flags.StringVar(&observer.ObserverBTF, "btf", "", "Location of btf")
	flags.StringVar(&observer.ObserverExecve.Observer__program,
		"bpf-execve", "", "Location of bpf_execve.o program")
	flags.StringVar(&observer.ObserverFork.Observer__program,
		"bpf-fork", "bpf_fork.o", "Location of fork bpf program")
	flags.StringVar(&observer.ObserverTCPConnect.Observer__program,
		"bpf-tcpmon", "bpf_tcpmon.o", "Location of bpf_tcpmon.o program")
	flags.StringVar(&observer.ObserverStreamConnect.Observer__program,
		"bpf-stream-connect", "bpf_stream_connect.o", "Location of bpf_stream_connect.o program")
	flags.StringVar(&observer.ObserverTCPConnectRet.Observer__program,
		"bpf-tcpmonret", "bpf_tcpmonret.o", "Location of bpf_tcpmon.o program")
	flags.StringVar(&observer.ObserverBind.Observer__program,
		"bpf-bind", "bpf_bind.o", "Location of bpf_bind.o program")
	flags.StringVar(&observer.ObserverGetPort.Observer__program,
		"bpf-get-port", "bpf_get_port.o", "Location of bpf_get_port.o program")
	flags.StringVar(&observer.ObserverListen.Observer__program,
		"bpf-listen", "bpf_listen.o", "Location of bpf_listen.o program")
	flags.StringVar(&observer.ObserverSockopsEstablished.Observer__program,
		"bpf-sockops", "bpf_sockops.o", "Location of bpf_sockops.o program")
	flags.StringVar(&observer.ObserverSkmsgTLS.Observer__program,
		"bpf-skmsg-tls", "bpf_skmsg_tls.o", "Location of bpf_skmsg_tls.o program")
	flags.StringVar(&observer.ObserverCgrpIngress.Observer__program,
		"bpf-ingress-tls", "bpf_cgrp_in_tls.o", "Location of bpf_cgrp_in_tls.o program")
	flags.StringVar(&observer.ObserverTLSEvent.Observer__program,
		"bpf-event-tls", "bpf_event_tls.o", "Location of bpf_event_tls.o program")
	flags.StringVar(&observer.ProcFS,
		"procfs", "/proc/", "Location of procfs to consume existing PIDs")
	flags.StringVar(&observer.KernelVersion, "kernel", "", "Kernel version")
	flags.IntVar(&observer.Verbosity, "verbose", 0, "set verbosity level")
	flags.BoolP("execve", "e", false, "Enable execve events")
	flags.BoolP("tls", "t", false, "Enable tls events")
	flags.BoolVarP(&observer.SetPidMax, "set-pid-max", "", false, "Configures pid_max procFS requirements on startup")
	flags.IntVar(&processCacheSize, "process-cache-size", 32768, "Size of the process cache")
	flags.StringVar(&exportFilename, "export-filename", "", "Filename for JSON export. Disabled by default")
	flags.IntVar(&exportFileMaxSizeMB, "export-file-max-size-mb", 10, "Size in MB for rotating JSON export files")
	flags.IntVar(&exportFileMaxBackups, "export-file-max-backups", 5, "Number of rotated JSON export files to retain")
	flags.BoolVar(&exportFileCompress, "export-file-compress", true, "Compress rotated JSON export files")
	flags.String("log-level", "info", "Set log level")
	flags.BoolVar(&enableK8sAPI, "enable-k8s-api", false, "Access Kubernetes API to associate FGS events with Kubernetes pods")
	viper.BindPFlags(flags)
}

func hubbleFGSMain() {
	cmd.Execute()
}
