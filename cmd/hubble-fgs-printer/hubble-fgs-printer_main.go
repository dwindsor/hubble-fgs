package main

import (
	"fmt"

	"github.com/covalentio/hubble-fgs/pkg/logger"
	"github.com/covalentio/hubble-fgs/pkg/reader"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	observerDir = "/sys/fs/bpf/tcpmon/"

	cmd *cobra.Command
)

func hubbleFGSPrinter() {
	log := logger.GetLogger()
	if err := reader.ObserverReceiver(log); err != nil {
		fmt.Printf("ObserverReceiver failed: %s\n", err)
	}
}

func init() {
	cmd = &cobra.Command{
		Use:   "hubble-fgs-printer",
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
