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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"github.com/isovalent/hubble-fgs/pkg/config"
	flb "github.com/isovalent/hubble-fgs/pkg/dpu/exporter/fluentbit"
)

// Manager manages the FluentBit configuration for the AGW-local
// FluentBit instance. It writes a YAML config to configPath whenever
// log export destinations change (syslog, ipfix, timescape, splunk).
type Manager struct {
	configPath string
	socketPath string
	config     flb.FluentBitConfig
	mu         sync.Mutex
	reloadCh   chan struct{}
}

const (
	reloadBaseDelay = 200 * time.Millisecond
	reloadMaxDelay  = 30 * time.Second
	httpPort        = "2020"
	reloadPath      = "/api/v2/reload"
	metricsPath     = "/api/v1/metrics"
)

// NewManager creates a new FluentBit config manager for the AGW-local
// FluentBit instance. configPath is the YAML config file to write, and
// socketPath is the unix socket for the AGW syslog input.
func NewManager(configPath, socketPath string) *Manager {
	mgr := &Manager{
		configPath: configPath,
		socketPath: socketPath,
		reloadCh:   make(chan struct{}, 1),
	}
	go mgr.reloadWorker()
	return mgr
}

// Init writes the default FluentBit config (AGW JSON input + stdout output)
// so AGW's managed FluentBit instance can start immediately.
func (m *Manager) Init() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.config = m.defaultConfig()
	return m.writeConfig()
}

// RefreshConfig is a config library callback that handles log config changes.
// It mirrors the logic of AcceleratedFluentbitExporter.RefreshConfig but
// without DPU-specific concerns (no networking setup, no sysmgrctl).
func (m *Manager) RefreshConfig(oldCfg *v1alpha.ConfigObject, newCfg *v1alpha.ConfigObject) error {
	cfg := newCfg
	if newCfg == nil {
		cfg = oldCfg
	}
	if cfg == nil {
		return errors.New("nil config object in agw flb manager callback")
	}

	switch cfg.Type {
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG,
		v1alpha.ConfigType_CONFIG_TYPE_LOG_IPFIX,
		v1alpha.ConfigType_CONFIG_TYPE_LOG_TIMESCAPE,
		v1alpha.ConfigType_CONFIG_TYPE_LOG_SPLUNK:
		return m.handleLogConfig(cfg.Type, oldCfg, newCfg)
	default:
		return nil
	}
}

func (m *Manager) handleLogConfig(typ v1alpha.ConfigType, oldCfg, newCfg *v1alpha.ConfigObject) error {
	var oldLogConfigs map[string]*v1alpha.LogConfig
	var newLogConfigs map[string]*v1alpha.LogConfig

	switch typ {
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG:
		if oldCfg != nil {
			oldLogConfigs = oldCfg.GetConfigLogSyslog().Configs
		}
		if newCfg != nil {
			newLogConfigs = newCfg.GetConfigLogSyslog().Configs
		}
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_IPFIX:
		if oldCfg != nil {
			oldLogConfigs = oldCfg.GetConfigLogIpfix().Configs
		}
		if newCfg != nil {
			newLogConfigs = newCfg.GetConfigLogIpfix().Configs
		}
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_TIMESCAPE:
		if oldCfg != nil {
			oldLogConfigs = oldCfg.GetConfigLogTimescape().Configs
		}
		if newCfg != nil {
			newLogConfigs = newCfg.GetConfigLogTimescape().Configs
		}
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_SPLUNK:
		if oldCfg != nil {
			oldLogConfigs = oldCfg.GetConfigLogSplunk().Configs
		}
		if newCfg != nil {
			newLogConfigs = newCfg.GetConfigLogSplunk().Configs
		}
	}

	logConfigAdds, logConfigRemoves := config.DiffLogConfigMaps(oldLogConfigs, newLogConfigs)

	m.mu.Lock()

	newConfig := m.config
	for id := range logConfigRemoves {
		newConfig = flb.RemoveLogConfig(newConfig, id)
	}
	for _, logConfig := range logConfigAdds {
		var err error
		newConfig, err = flb.AddLogConfig(newConfig, typ, logConfig)
		if err != nil {
			m.mu.Unlock()
			logger.GetLogger().Error("failed to apply log export config to AGW FluentBit",
				logfields.Error, err, "type", typ)
			return err
		}
	}

	m.config = newConfig
	err := m.writeConfig()
	m.mu.Unlock()
	if err != nil {
		return err
	}

	m.requestReload()
	return nil
}

func (m *Manager) writeConfig() error {
	configData, err := yaml.Marshal(m.config)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(m.configPath), 0755); err != nil {
		return err
	}

	return os.WriteFile(m.configPath, configData, 0644)
}

func reloadURL() string {
	return "http://localhost:" + httpPort + reloadPath
}

// triggerReload POSTs to the FluentBit HTTP API to trigger a config reload.
func (m *Manager) triggerReload() error {
	url := reloadURL()
	client := &http.Client{Timeout: 2 * time.Second}
	mURL := "http://localhost:" + httpPort + metricsPath
	delay := reloadBaseDelay
	for attempt := 1; ; attempt++ {
		var err error
		if err = fluentBitReady(client, mURL); err != nil {
			err = fmt.Errorf("FluentBit metrics endpoint not ready: %w", err)
		}

		if err == nil {
			req, reqErr := http.NewRequest(http.MethodPost, url, nil)
			if reqErr != nil {
				return reqErr
			}
			resp, postErr := client.Do(req)
			if postErr == nil {
				body, readErr := io.ReadAll(resp.Body)
				resp.Body.Close()
				if readErr != nil {
					err = fmt.Errorf("failed to read FluentBit reload response: %w", readErr)
				}
				if resp.StatusCode == http.StatusOK {
					if err == nil {
						ok, reason := fluentBitReloadSucceeded(body)
						if ok {
							logger.GetLogger().Info("FluentBit config reload triggered",
								"url", url, "attempt", attempt)
							return nil
						}
						err = fmt.Errorf("FluentBit reload endpoint returned non-success payload: %s", reason)
					}
				} else if err == nil {
					err = fmt.Errorf("FluentBit reload returned status %d", resp.StatusCode)
				}
			} else {
				err = postErr
			}
		}

		if attempt == 1 || attempt%10 == 0 {
			logger.GetLogger().Warn("FluentBit reload request failed, retrying",
				"url", url, "attempt", attempt, "error", err)
		}

		time.Sleep(delay)
		delay *= 2
		if delay > reloadMaxDelay {
			delay = reloadMaxDelay
		}
	}
}

func (m *Manager) requestReload() {
	select {
	case m.reloadCh <- struct{}{}:
	default:
	}
}

func (m *Manager) reloadWorker() {
	for range m.reloadCh {
		_ = m.triggerReload()
	}
}

func fluentBitReady(client *http.Client, metricsURL string) error {
	resp, err := client.Get(metricsURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("metrics endpoint returned status %d", resp.StatusCode)
	}
	return nil
}

func fluentBitReloadSucceeded(body []byte) (bool, string) {
	type reloadResponse struct {
		Status *int   `json:"status"`
		Reload string `json:"reload"`
	}

	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return true, ""
	}

	var parsed reloadResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		// Older/newer Fluent Bit versions may return non-JSON payloads.
		// Treat HTTP 200 + non-JSON as success.
		return true, ""
	}

	if parsed.Status == nil || *parsed.Status == 0 {
		return true, ""
	}
	return false, strings.TrimSpace(trimmed)
}

// defaultConfig returns the base FluentBit config for AGW with a single
// JSON input on the AGW socket and a stdout output for debugging.
func (m *Manager) defaultConfig() flb.FluentBitConfig {
	cfg := flb.DefaultBaseConfig()
	cfg.Service.HTTPServer = "on"
	cfg.Service.HTTPListen = "0.0.0.0"
	cfg.Service.HTTPPort = httpPort
	cfg.Parsers = append(cfg.Parsers, flb.ParserSection{
		Name:   "json",
		Format: "json",
	})
	cfg.Pipeline.Inputs = append(cfg.Pipeline.Inputs, flb.InputSection{
		Name: "syslog",
		Tag:  "agw-input",
		Properties: map[string]string{
			"mode":      "unix_udp",
			"unix_perm": "0644",
			"path":      m.socketPath,
			"parser":    "json",
			"threaded":  "true",
		},
	})
	cfg.Pipeline.Outputs = append(cfg.Pipeline.Outputs, flb.DefaultStdoutOutput())
	return cfg
}
