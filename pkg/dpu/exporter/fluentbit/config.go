// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package fluentbit

import (
	"fmt"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"
)

// Default fluentbit config with DP and FWA inputs defined
func DefaultConfig() FluentBitConfig {
	config := DefaultBaseConfig()

	// Adding the default dp json parser and dp syslog input
	config.Parsers = append(config.Parsers, DefaultDpJsonParser())
	config.Parsers = append(config.Parsers, DefaultFwaJsonParser())
	config.Pipeline.Inputs = append(config.Pipeline.Inputs, DefaultDpSyslogInput())
	config.Pipeline.Inputs = append(config.Pipeline.Inputs, DefaultFwaSyslogInput())
	// config.Pipeline.Outputs = append(config.Pipeline.Outputs, DefaultStdoutOutput) // Debugging only

	return config
}

// Adds the log output for the specified type based on the log config.
func AddLogConfig(fbc FluentBitConfig, typ v1alpha.ConfigType, logCfg *v1alpha.LogConfig) (FluentBitConfig, error) {
	// Adding custom fields for different log export locations
	logOutput := OutputSection{}
	switch typ {
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG:
		logOutput = DefaultDpSyslogOutput()
		logOutput.Properties["mode"] = logCfg.Protocol
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_TIMESCAPE:
		logOutput = DefaultDpTimescapeOutput()
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_SPLUNK:
		return fbc, fmt.Errorf("splunk fluentbit support not implemented")
	default:
		return fbc, fmt.Errorf("fluentbit support not implemented for config type %s", typ)
	}

	// Fields that are consistent for all outputs
	logOutput.Match = "*" // HACK: should be scoped to only pick up the correct input tags
	logOutput.Alias = logCfg.Id
	logOutput.Properties["host"] = logCfg.Host
	logOutput.Properties["port"] = logCfg.Port

	// Configuring the certificates if TLS is enabled
	if logCfg.Tls {
		err := AddTlsOutputProperties(&logOutput, logCfg.Id, logCfg)
		if err != nil {
			return fbc, err
		}
	}

	// Checking if the output alias already exists and replacing it if it does, or just appending to the end
	for i, val := range fbc.Pipeline.Outputs {
		if val.Alias == logOutput.Alias {
			// Deleting value, order doesn't matter so moving last index to replace deleted index
			fbc.Pipeline.Outputs[i] = fbc.Pipeline.Outputs[len(fbc.Pipeline.Outputs)-1]
			fbc.Pipeline.Outputs = fbc.Pipeline.Outputs[:len(fbc.Pipeline.Outputs)-1]
			break
		}
	}
	fbc.Pipeline.Outputs = append(fbc.Pipeline.Outputs, logOutput)
	return fbc, nil
}

// Removes the log output that has an alias equal to the passed id.  If it does
// not exist, this is a noop.
func RemoveLogConfig(fbc FluentBitConfig, id string) FluentBitConfig {
	// Keep only outputs that don't have the matching alias
	filteredOutputs := []OutputSection{}
	for _, output := range fbc.Pipeline.Outputs {
		if output.Alias != id {
			filteredOutputs = append(filteredOutputs, output)
		}
	}
	fbc.Pipeline.Outputs = filteredOutputs
	return fbc
}

// Adds TLS properties to an output section in place
// Files are created in the FLB_SSH_DIR directory for the secrets
// Returns error if any file operations fail
func AddTlsOutputProperties(output *OutputSection, _ string, logConfig *v1alpha.LogConfig) error {
	// Handle authentication based on the oneof auth field
	switch auth := logConfig.Auth.(type) {
	case *v1alpha.LogConfig_Token:
		// Creating field for splunk token
		if auth.Token != nil && auth.Token.Token != "" {
			output.Properties["splunk_token"] = auth.Token.Token
		}
	case *v1alpha.LogConfig_BasicAuth:
		// Creating fields for basic username and password
		if auth.BasicAuth != nil {
			if auth.BasicAuth.Username != "" {
				output.Properties["http_user"] = auth.BasicAuth.Username
			}
			if auth.BasicAuth.Password != "" {
				output.Properties["http_passwd"] = auth.BasicAuth.Password
			}
		}
	case *v1alpha.LogConfig_Mtls:
		// mTLS configuration - certificates will be handled by cert manager
		// For now, just enable TLS
		output.Properties["tls"] = "On"
	}

	// Enable TLS if configured
	if logConfig.Tls {
		output.Properties["tls"] = "On"
	}

	return nil
}
