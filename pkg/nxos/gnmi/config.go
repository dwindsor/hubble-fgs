// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package gnmi

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
)

const (
	// DefaultGrpcPort is the default gNMI port used by NXOS.
	DefaultGrpcPort = "50052"
	// DefaultGrpcUser is the default gNMI username used by NXOS.
	DefaultGrpcUser = "__svc_sas_control"
	// DefaultSASConfigFile is the default config file path used to load NX_GRPC_PASS.
	DefaultSASConfigFile = "/etc/sas.cfg"
)

// HandlerConfig contains configuration for creating a gNMI handler.
type HandlerConfig struct {
	// Address is the target address (host:port)
	Address string
	// Username for gNMI authentication
	Username string
	// Password for gNMI authentication
	Password string
	// Insecure disables TLS
	Insecure bool
	// SkipVerify skips TLS certificate verification
	SkipVerify bool
	// TLSCA is the path to the CA certificate file
	TLSCA string
	// TLSCert is the path to the client certificate file
	TLSCert string
	// TLSKey is the path to the client key file
	TLSKey string
	// Timeout for gNMI operations
	Timeout time.Duration
}

// DefaultHandlerConfig returns a HandlerConfig with sensible defaults.
func DefaultHandlerConfig() *HandlerConfig {
	return &HandlerConfig{
		Timeout:    30 * time.Second,
		SkipVerify: true,
	}
}

// LoadCredentialsFromEnvAndConfig reads gNMI connection credentials from
// environment variables and a config file.
func LoadCredentialsFromEnvAndConfig(configFile string) (*HandlerConfig, error) {
	// Get IP from environment variable (required)
	ip, ok := os.LookupEnv("NX_GRPC_IP")
	if !ok {
		return nil, fmt.Errorf("NX_GRPC_IP environment variable is required")
	}

	// Get port from environment variable
	port, ok := os.LookupEnv("NX_GRPC_PORT")
	if !ok {
		port = DefaultGrpcPort
	}

	// Get username from environment variable (optional, default __svc_sas_control)
	user, ok := os.LookupEnv("NX_GRPC_USER")
	if !ok {
		user = DefaultGrpcUser
	}

	// Read password from config file
	v := viper.New()
	v.SetConfigFile(configFile)
	v.SetConfigType("env")
	err := v.ReadInConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	pass := v.GetString("NX_GRPC_PASS")
	if pass == "" {
		return nil, fmt.Errorf("NX_GRPC_PASS not found in config")
	}

	return &HandlerConfig{
		Address:    ip + ":" + port,
		Username:   user,
		Password:   pass,
		SkipVerify: true,
	}, nil
}
