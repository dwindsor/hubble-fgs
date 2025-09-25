package fluentbit

import (
	"fmt"
	"os"
	"path/filepath"

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
		logOutput.Properties["mode"] = logCfg.Mode
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_IPFIX:
		return fbc, fmt.Errorf("ipfix fluentbit support not implemented")
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
func AddTlsOutputProperties(output *OutputSection, id string, logConfig *v1alpha.LogConfig) error {
	// Creating field for splunk token
	if logConfig.Token != "" {
		output.Properties["splunk_token"] = logConfig.Token
	}

	// Creating fields for basic username and password
	if logConfig.Username != "" {
		output.Properties["http_user"] = logConfig.Username
	}
	if logConfig.Password != "" {
		output.Properties["http_passwd"] = logConfig.Password
	}

	// Making sure the .ssh directory for hypershield exists
	err := os.MkdirAll(FLB_SSH_DIR, 0700)
	if err != nil {
		return err
	}
	output.Properties["tls.ca_path"] = FLB_SSH_DIR

	// Creating local files to store any certificates
	caFile := id + ".ca"
	certFile := id + ".cert"
	keyFile := id + ".key"
	if logConfig.Ca != "" {
		err = os.WriteFile(filepath.Join(FLB_SSH_DIR, caFile), []byte(logConfig.Ca), 0644)
		if err != nil {
			return err
		}
		output.Properties["tls.ca_file"] = filepath.Join(FLB_SSH_DIR, caFile)
		output.Properties["tls"] = "On"
	}
	if logConfig.Cert != "" {
		err = os.WriteFile(filepath.Join(FLB_SSH_DIR, certFile), []byte(logConfig.Cert), 0644)
		if err != nil {
			return err
		}
		output.Properties["tls.crt_file"] = filepath.Join(FLB_SSH_DIR, certFile)
		output.Properties["tls"] = "On"
	}
	if logConfig.Key != "" {
		err = os.WriteFile(filepath.Join(FLB_SSH_DIR, keyFile), []byte(logConfig.Key), 0600)
		if err != nil {
			return err
		}
		output.Properties["tls.key_file"] = filepath.Join(FLB_SSH_DIR, keyFile)
		output.Properties["tls"] = "On"
	}
	if logConfig.KeyPassword != "" {
		output.Properties["tls.key_passwd"] = logConfig.KeyPassword
		output.Properties["tls"] = "On"
	}
	return nil
}
