package main

import (
	"github.com/covalentio/hubble-fgs/pkg/observer"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	observerDir = "/sys/fs/bpf/tcpmon/"

	cmd *cobra.Command
)

func hubbleFGSPrinter() {
	kprobe := observer.NewObserverKprobe(observerDir)
	kprobe.ObserverReceiver()
}

func init() {
	cmd = &cobra.Command{
		Use:   "hubble-fgs SOURCE_DIR BUCKET",
		Short: "Hubble FGS",
		Run: func(cmd *cobra.Command, args []string) {
			hubbleFGSPrinter()
		},
	}

	flags := cmd.PersistentFlags()
	flags.BoolP("debug", "d", true, "Enable debug messages")
	viper.BindPFlags(flags)
}

func hubbleFGSMainPrinter() {
	cmd.Execute()
}
