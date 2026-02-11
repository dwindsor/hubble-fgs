// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// Package switchmetrics provides functionality for collecting and pushing switch
// metrics to a Prometheus server using the standard remote write protocol.

package switchmetrics

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/golang/snappy"

	"github.com/golang/protobuf/proto" //nolint:staticcheck // Required for Prometheus prompb compatibility

	"github.com/prometheus/prometheus/prompb"
)

// PrometheusPusher handles pushing metrics to controller's Prometheus server using the standard remote write protocol
type PrometheusPusher struct {
	config           *PrometheusPushConfig
	metricsCollector *MetricsCollector
	httpClient       *http.Client
	ctx              context.Context
	cancel           context.CancelFunc
}

func NewPrometheusPusher(ctx context.Context, collector *MetricsCollector, config *PrometheusPushConfig) *PrometheusPusher {
	httpClient := createHTTPClient(config)
	ctx, cancel := context.WithCancel(ctx)

	return &PrometheusPusher{
		config:           config,
		metricsCollector: collector,
		httpClient:       httpClient,
		ctx:              ctx,
		cancel:           cancel,
	}
}

func createHTTPClient(config *PrometheusPushConfig) *http.Client {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.InsecureSkipVerify,
	}

	// Load client certificates if provided
	if config.CertFile != "" && config.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			logger.GetLogger().Warn("Failed to load client certificates", "error", err)
		} else {
			tlsConfig.Certificates = []tls.Certificate{cert}
			logger.GetLogger().Debug("Loaded client certificates for mTLS")
		}
	}

	// Load CA certificate if provided
	if config.CAFile != "" {
		caCert, err := os.ReadFile(config.CAFile)
		if err != nil {
			logger.GetLogger().Warn("Failed to load CA certificate", "error", err)
		} else {
			caCertPool := x509.NewCertPool()
			if caCertPool.AppendCertsFromPEM(caCert) {
				tlsConfig.RootCAs = caCertPool
				logger.GetLogger().Debug("Loaded CA certificate")
			} else {
				logger.GetLogger().Warn("Failed to parse CA certificate")
			}
		}
	}

	return &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			MaxIdleConns:    DefaultMaxIdleConns,
			IdleConnTimeout: 0, // Never timeout idle connections (keep forever),
			MaxConnsPerHost: 1, // Only 1 total connection per host
			// Keep-alive settings for persistent connection
			DisableKeepAlives:     false,            // Enable keep-alive
			ResponseHeaderTimeout: 30 * time.Second, // Response header timeout
			ExpectContinueTimeout: 2 * time.Second,  // Expect: 100-continue timeout
		},
	}
}

// Start begins the periodic pushing of metrics to the Prometheus server
func (pp *PrometheusPusher) Start() error {
	logger.GetLogger().Debug("Starting Prometheus metrics pusher",
		"controller_url", pp.config.ControllerURL,
		"push_interval", pp.config.PushInterval)

	// Start push loop in goroutine
	go pp.pushLoop()

	return nil
}

// Stop signals the pusher to stop and performs any necessary cleanup
func (pp *PrometheusPusher) Stop() error {
	logger.GetLogger().Info("Stopping Prometheus pusher")
	pp.cancel()
	return nil
}

// PushMetrics performs periodic push of metrics to the Prometheus server, with retry logic
func (pp *PrometheusPusher) pushLoop() {
	ticker := time.NewTicker(pp.config.PushInterval)
	defer ticker.Stop()

	// Initial push
	pp.pushMetrics(pp.ctx)

	for {
		select {
		case <-pp.ctx.Done():
			logger.GetLogger().Info("Stopping metrics pusher")
			return
		case <-ticker.C:
			pp.pushMetrics(pp.ctx)
		}
	}
}

// pushMetrics retrieves current metrics, converts to Prometheus format,
// and sends to controller with retry logic
func (pp *PrometheusPusher) pushMetrics(ctx context.Context) {
	// Get current metrics from collector
	if pp.metricsCollector == nil {
		logger.GetLogger().Warn("Metrics collector not available")
		return
	}

	currentMetrics := pp.metricsCollector.GetCurrentMetrics()
	if currentMetrics == nil {
		logger.GetLogger().Warn("No current metrics available")
		return
	}

	// Convert to Prometheus format
	timeSeries := pp.convertToTimeSeries(currentMetrics)

	// Create remote write request
	writeRequest := &prompb.WriteRequest{
		Timeseries: timeSeries,
	}

	// Push to controller with retry logic
	for attempt := 0; attempt <= pp.config.RetryAttempts; attempt++ {
		if err := pp.sendWriteRequest(writeRequest); err != nil {
			logger.GetLogger().Warn("Failed to push metrics",
				"attempt", attempt+1,
				"max_attempts", pp.config.RetryAttempts+1,
				"error", err)

			if attempt < pp.config.RetryAttempts {
				backoffDuration := pp.config.RetryBackoff * time.Duration(attempt+1)
				select {
				case <-ctx.Done():
					logger.GetLogger().Error("Context cancelled during metrics push retry backoff")
					return
				case <-time.After(backoffDuration):
					logger.GetLogger().Info("Retrying after backoff", "backoff", backoffDuration)
					continue
				}
			}

			logger.GetLogger().Error("Failed to push metrics after all retry attempts", "error", err)
		} else {
			logger.GetLogger().Info("Successfully pushed metrics to controller",
				"metrics_count", len(timeSeries),
				"memory_mb", currentMetrics.TotalPhysicalMemoryKBUsage/1024,
				"cpu_percent", currentMetrics.CPUUsagePercent,
				"policies", currentMetrics.PolicyK8sIDs,
				"rules", currentMetrics.PolicyDPURules)
			break
		}
	}
}

// convertToTimeSeries converts CurrentMetrics to Prometheus TimeSeries format
func (pp *PrometheusPusher) convertToTimeSeries(metrics *CurrentMetrics) []prompb.TimeSeries {
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)
	baseLabels := pp.createBaseLabels()

	var timeSeries []prompb.TimeSeries

	// Memory usage metric
	timeSeries = append(timeSeries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{
			Name:  "__name__",
			Value: "agw_memory_usage_mb",
		}),
		Samples: []prompb.Sample{
			{
				Value:     metrics.TotalPhysicalMemoryKBUsage,
				Timestamp: timestamp,
			},
		},
	})

	// CPU usage metric
	timeSeries = append(timeSeries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{
			Name:  "__name__",
			Value: "agw_cpu_usage_percent",
		}),
		Samples: []prompb.Sample{
			{
				Value:     metrics.CPUUsagePercent,
				Timestamp: timestamp,
			},
		},
	})

	// Policy count metric
	timeSeries = append(timeSeries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{
			Name:  "__name__",
			Value: "agw_policy_count",
		}),
		Samples: []prompb.Sample{
			{
				Value:     float64(metrics.PolicyK8sIDs),
				Timestamp: timestamp,
			},
		},
	})

	// DPU rules count metric
	timeSeries = append(timeSeries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{
			Name:  "__name__",
			Value: "agw_dpu_rules_count",
		}),
		Samples: []prompb.Sample{
			{
				Value:     float64(metrics.PolicyDPURules),
				Timestamp: timestamp,
			},
		},
	})

	// Error counters
	timeSeries = append(timeSeries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{
			Name:  "__name__",
			Value: "agw_dpu_insert_errors_total",
		}),
		Samples: []prompb.Sample{
			{
				Value:     float64(metrics.PolicyDPUInsertErrors),
				Timestamp: timestamp,
			},
		},
	})

	timeSeries = append(timeSeries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{
			Name:  "__name__",
			Value: "agw_dpu_update_errors_total",
		}),
		Samples: []prompb.Sample{
			{
				Value:     float64(metrics.PolicyDPUUpdateErrors),
				Timestamp: timestamp,
			},
		},
	})

	timeSeries = append(timeSeries, prompb.TimeSeries{
		Labels: append(baseLabels, prompb.Label{
			Name:  "__name__",
			Value: "agw_dpu_delete_errors_total",
		}),
		Samples: []prompb.Sample{
			{
				Value:     float64(metrics.PolicyDPUDeleteErrors),
				Timestamp: timestamp,
			},
		},
	})

	return timeSeries
}

func (pp *PrometheusPusher) createBaseLabels() []prompb.Label {
	labels := []prompb.Label{}

	// Add external labels from config
	for name, value := range pp.config.ExternalLabels {
		labels = append(labels, prompb.Label{
			Name:  name,
			Value: value,
		})
	}

	labels = append(labels, prompb.Label{
		Name:  "instance",
		Value: pp.config.SerialNumber,
	})

	return labels
}

// sendWriteRequest sends the given WriteRequest to the Prometheus server
// with appropriate headers and authentication for remote write protocol
func (pp *PrometheusPusher) sendWriteRequest(req *prompb.WriteRequest) error {
	// Serialize the request
	data, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal write request: %w", err)
	}

	// Compress with snappy
	compressed := snappy.Encode(nil, data)

	// Create HTTP request
	httpReq, err := http.NewRequest("POST", pp.config.ControllerURL, bytes.NewReader(compressed))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	httpReq.Header.Set("Content-Encoding", "snappy")
	httpReq.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
	httpReq.Header.Set("User-Agent", "agw-metrics-pusher/1.0")

	// Set authentication
	if pp.config.BearerToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+pp.config.BearerToken)
	} else if pp.config.Username != "" && pp.config.Password != "" {
		httpReq.SetBasicAuth(pp.config.Username, pp.config.Password)
	}

	// Send request
	resp, err := pp.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("controller returned error status %d: %s", resp.StatusCode, string(body))
	}

	logger.GetLogger().Info("Successfully sent metrics to controller", "status", resp.StatusCode)
	return nil
}
