package main

import (
	"os"

	"github.com/covalentio/hubble-fgs/pkg/reader"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	observerDir = "/sys/fs/bpf/tcpmon/"

	cmd *cobra.Command
)

func hubbleFGSPrinter() {
	// Use JSON formatter for hubble-fgs-printer.
	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	log.SetLevel(logrus.TraceLevel)
	log.SetOutput(os.Stdout)
	if err := reader.ObserverReceiver(log); err != nil {
		log.WithError(err).Fatal("ObserverReceiver failed")
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
