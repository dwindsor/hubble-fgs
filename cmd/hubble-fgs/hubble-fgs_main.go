package main

import (
	"github.com/covalentio/hubble-fgs/pkg/bpf"
	"github.com/covalentio/hubble-fgs/pkg/defaults"
	"github.com/covalentio/hubble-fgs/pkg/observer"
	"github.com/covalentio/hubble-fgs/pkg/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"context"
	"math"

	"golang.org/x/sys/unix"
)

var (
	observerDir = "/sys/fs/bpf/tcpmon/"

	cmd *cobra.Command
)

func configureResourceLimits() error {
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: math.MaxUint64,
		Max: math.MaxUint64,
	})
}

func hubbleFGSExecute() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	configureResourceLimits()
	kprobe := observer.NewObserverKprobe(observerDir)
	go server.ServeEvents(kprobe, ctx, defaults.DefaultUnixSock)
	kprobe.Start()
}

func init() {
	cmd = &cobra.Command{
		Use:   "hubble-fgs SOURCE_DIR BUCKET",
		Short: "Hubble FGS",
		Run: func(cmd *cobra.Command, args []string) {
			hubbleFGSExecute()
		},
	}

	flags := cmd.PersistentFlags()

	flags.BoolP("debug", "d", true, "Enable debug messages")
	flags.StringVar(&observer.ObserverExecve__program,
		"bpf-execve", "./bpf/bpf_execve.o", "Location of bpf_execve.o program")
	flags.StringVar(&observer.ObserverExecveat__program,
		"bpf-execveat", "./bpf/bpf_execveat.o", "Location of bpf_execveat.o program")
	flags.StringVar(&observer.ObserverTCPConnect__program,
		"bpf-tcpmon", "./bpf/bpf_tcpmon.o", "Location of bpf_tcpmon.o program")
	flags.StringVar(&observer.ObserverTCPConnectRet__program,
		"bpf-tcpmonret", "./bpf/bpf_tcpmonret.o", "Location of bpf_tcpmon.o program")
	flags.StringVar(&observer.ProcFS,
		"procfs", "/proc/", "Location of procfs to consume existing PIDs")
	viper.BindPFlags(flags)
}

func hubbleFGSMain() {
	cmd.Execute()
}
