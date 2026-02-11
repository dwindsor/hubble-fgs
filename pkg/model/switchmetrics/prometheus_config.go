// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package switchmetrics

import (
	"time"
)

const (
	// DefaultPrometheusPushInterval is the default interval for pushing metrics to Prometheus
	DefaultPrometheusPushInterval = 30 * time.Second

	// DefaultPrometheusPushTimeout is the default timeout for HTTP requests to Prometheus
	DefaultPrometheusPushTimeout = 30 * time.Second

	// DefaultPrometheusPushRetryAttempts is the default number of retry attempts for pushing metrics
	DefaultPrometheusPushRetryAttempts = 3

	// DefaultPrometheusPushRetryBackoff is the default backoff duration between retry attempts
	DefaultPrometheusPushRetryBackoff = 3 * time.Second

	// DefaultPrometheusInsecureSkipVerify indicates whether to skip TLS verification by default
	DefaultPrometheusInsecureSkipVerify = false

	// DefaultPrometheusControllerURL is the default URL for the controller's Prometheus remote write endpoint
	DefaultPrometheusControllerURL = ""

	// DefaultPrometheusAuthUsername is the default username for authentication with Prometheus
	DefaultPrometheusAuthUsername = ""

	// DefaultPrometheusAuthPassword is the default password for authentication with Prometheus
	DefaultPrometheusAuthPassword = ""

	// DefaultPrometheusAuthBearerToken is the default bearer token for authentication with Prometheus
	DefaultPrometheusAuthBearerToken = ""

	// DefaultPrometheusTLSCertFile is the default path to the TLS certificate file for Prometheus
	DefaultPrometheusTLSCertFile = ""

	// DefaultPrometheusTLSKeyFile is the default path to the TLS key file for Prometheus
	DefaultPrometheusTLSKeyFile = ""

	// DefaultPrometheusTLSCAFile is the default path to the TLS CA file for Prometheus
	DefaultPrometheusTLSCAFile = ""

	// DefaultMaxIdleConns is the default maximum number of idle connections for the Prometheus HTTP client
	DefaultMaxIdleConns = 1
)

// PrometheusPushConfig contains configuration for pushing metrics to Prometheus
type PrometheusPushConfig struct {
	ControllerURL string        // Controller's Prometheus remote write endpoint
	PushInterval  time.Duration // How often to push metrics
	Timeout       time.Duration // HTTP request timeout
	RetryAttempts int           // Number of retry attempts
	RetryBackoff  time.Duration // Backoff between retries

	// Authentication
	Username    string
	Password    string
	BearerToken string

	// TLS config
	InsecureSkipVerify bool
	CertFile           string
	KeyFile            string
	CAFile             string

	// Labels to add to all metrics
	ExternalLabels map[string]string

	// Switch-specific labels
	SerialNumber string
}

func DefaultPrometheusPushConfig() *PrometheusPushConfig {
	return &PrometheusPushConfig{
		ControllerURL:      "",
		PushInterval:       DefaultPrometheusPushInterval,
		Timeout:            DefaultPrometheusPushTimeout,
		RetryAttempts:      DefaultPrometheusPushRetryAttempts,
		RetryBackoff:       DefaultPrometheusPushRetryBackoff,
		Username:           "",
		Password:           "",
		BearerToken:        "",
		InsecureSkipVerify: true, // Set to true for development
		CertFile:           DefaultPrometheusTLSCertFile,
		KeyFile:            DefaultPrometheusTLSKeyFile,
		CAFile:             DefaultPrometheusTLSCAFile,
		ExternalLabels: map[string]string{
			"job": "smartswitch",
		},
	}
}

func (config *PrometheusPushConfig) SetControllerURL(url string) {
	config.ControllerURL = url
}

func (config *PrometheusPushConfig) SetUsername(username string) {
	config.Username = username
}

func (config *PrometheusPushConfig) SetPassword(password string) {
	config.Password = password
}

func (config *PrometheusPushConfig) SetSwitchSerialNumber(serialNumber string) {
	config.SerialNumber = serialNumber
}
