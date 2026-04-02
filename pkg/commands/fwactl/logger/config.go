// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package logger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"github.com/isovalent/hubble-fgs/pkg/dpu"
	"github.com/isovalent/hubble-fgs/pkg/dpu/exporter"
	flb "github.com/isovalent/hubble-fgs/pkg/dpu/exporter/fluentbit"
)

var (
	CONFIG_TYPE string
	SERVICE_MAC string
)

// loggerConfigCmd represents the logger config command
var loggerConfigCmd = &cobra.Command{
	Use:          "config [file]",
	SilenceUsage: true,
	Short:        "Configure logger by sending configuration to daf-logger if running",
	Long: `Configure logger takes configuration from a file and sends it to daf-logger.  This replaces
any existing logger configuration.  It is in the format:
{
  "123": {
    "id": "123",
    "name": "string",
    "description": "string",
	"host": "string",
	"port": "string",
	"mode": "string",
	"username": "string",
	"password": "string",
	"token": "string",
	"tls": "bool"
	"ca": "string",
	"cert": "string",
	"key": "string",
	"keyPassword": "string"
  }
}`,
	RunE: func(_ *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("missing file")
		}
		cfg, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}

		// Confirming config is valid
		var logMap map[string]*v1alpha.LogConfig
		err = json.Unmarshal(cfg, &logMap)
		if err != nil {
			return err
		}

		// Checking config type
		var typ v1alpha.ConfigType
		switch CONFIG_TYPE {
		case "syslog":
			typ = v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG
		case "timescape":
			typ = v1alpha.ConfigType_CONFIG_TYPE_LOG_TIMESCAPE
		case "splunk":
			typ = v1alpha.ConfigType_CONFIG_TYPE_LOG_SPLUNK
		default:
			return fmt.Errorf("could not create config, unknown type %s", CONFIG_TYPE)
		}

		// Building the log exporter object
		logExporter := exporter.NewAcceleratedFluentbitExporter("", dpu.EXPORTER_CONFIG_PATH)
		err = logExporter.Init(context.Background())
		if err != nil {
			return err
		}
		logExporter.Fluentbit.NpuMac = SERVICE_MAC

		// Adding all export locations to the config
		config := logExporter.Fluentbit.Config
		for _, cfg := range logMap {
			config, err = flb.AddLogConfig(config, typ, cfg)
			if err != nil {
				return err
			}
		}
		err = logExporter.Fluentbit.UpdateConfig(config)
		if err != nil {
			return err
		}
		return nil
	},
}

func init() {
	loggerConfigCmd.PersistentFlags().StringVar(&SERVICE_MAC, "mac", "00:0c:0c:0c:0c:0c", "sets the service mac address")
	loggerConfigCmd.PersistentFlags().StringVar(&CONFIG_TYPE, "type", "syslog", "sets log configuration type [syslog, timescape, splunk]")
	LoggerCmd.AddCommand(loggerConfigCmd)
}
