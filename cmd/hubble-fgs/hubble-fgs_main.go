package main

import (
	"github.com/covalentio/hubble-fgs/pkg/bpf"
	"github.com/covalentio/hubble-fgs/pkg/defaults"
	"github.com/covalentio/hubble-fgs/pkg/observer"
	"github.com/covalentio/hubble-fgs/pkg/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

var (
	observerDir     = "/sys/fs/bpf/tcpmon/"
	varRunHubbleFGS = "/var/run/hubble-fgs/"

	cmd *cobra.Command
)

func hubbleFGSExecute() error {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		observer.PrintStats()
		os.Exit(1)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.ConfigureResourceLimits()
	kprobe := observer.NewObserverKprobe(observerDir, viper.GetBool("debug"))
	go server.ServeEvents(kprobe, ctx, defaults.DefaultUnixSock)
	return kprobe.Start()
}

func init() {
	cmd = &cobra.Command{
		Use:   "hubble-fgs SOURCE_DIR BUCKET",
		Short: "Hubble FGS",
		Run: func(cmd *cobra.Command, args []string) {
			if err := hubbleFGSExecute(); err != nil {
				fmt.Printf("%s", err)
			}
		},
	}

	flags := cmd.PersistentFlags()

	flags.BoolP("debug", "d", false, "Enable debug messages")
	flags.StringVar(&observer.ObserverBTF, "btf", "", "Location of btf")
	flags.StringVar(&observer.ObserverExecve.Observer__program,
		"bpf-execve", varRunHubbleFGS+"bpf_execve.o", "Location of bpf_execve.o program")
	flags.StringVar(&observer.ObserverExecveat.Observer__program,
		"bpf-execveat", varRunHubbleFGS+"bpf_execveat.o", "Location of bpf_execveat.o program")
	flags.StringVar(&observer.ObserverFork.Observer__program,
		"bpf-fork", varRunHubbleFGS+"./bpf/bpf_fork.o", "Location of fork bpf program")
	flags.StringVar(&observer.ObserverTCPConnect.Observer__program,
		"bpf-tcpmon", varRunHubbleFGS+"bpf_tcpmon.o", "Location of bpf_tcpmon.o program")
	flags.StringVar(&observer.ObserverTCPConnectRet.Observer__program,
		"bpf-tcpmonret", varRunHubbleFGS+"bpf_tcpmonret.o", "Location of bpf_tcpmon.o program")
	flags.StringVar(&observer.ObserverBind.Observer__program,
		"bpf-bind", varRunHubbleFGS+"bpf_bind.o", "Location of bpf_bind.o program")
	flags.StringVar(&observer.ObserverGetPort.Observer__program,
		"bpf-get-port", varRunHubbleFGS+"bpf_get_port.o", "Location of bpf_get_port.o program")
	flags.StringVar(&observer.ObserverListen.Observer__program,
		"bpf-listen", varRunHubbleFGS+"bpf_listen.o", "Location of bpf_listen.o program")
	flags.StringVar(&observer.ProcFS,
		"procfs", "/proc/", "Location of procfs to consume existing PIDs")
	flags.StringVar(&observer.KernelVersion, "kernel", "", "Kernel version")
	flags.IntVar(&observer.Verbosity, "verbose", 0, "set verbosity level")
	flags.BoolVarP(&observer.EnableExecve, "execve", "e", false, "Enable execve events")
	viper.BindPFlags(flags)
}

func hubbleFGSMain() {
	cmd.Execute()
}
