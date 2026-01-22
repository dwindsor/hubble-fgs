// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package switchevents

import (
	"sync"
)

const (
	TIMESCAPE_USERNAME = "timescape_push_api"
)

// TimescapeConfig holds the timescape client configuration
type TimescapeConfig struct {
	ClientEnabled bool   `json:"client_enabled"`
	Endpoint      string `json:"endpoint"`
	Username      string `json:"username"`
	Password      string `json:"-"` // Don't serialize password in JSON
}

// TimescapeConfigManager manages the timescape configuration with thread safety
type TimescapeConfigManager struct {
	mu     sync.RWMutex
	config *TimescapeConfig
}

var (
	timescapeConfigManagerInstance *TimescapeConfigManager
	timescapeConfigManagerOnce     sync.Once
)

// GetTimescapeConfigManager returns the singleton instance of TimescapeConfigManager
func GetTimescapeConfigManager() *TimescapeConfigManager {
	timescapeConfigManagerOnce.Do(func() {
		timescapeConfigManagerInstance = &TimescapeConfigManager{
			config: &TimescapeConfig{},
		}
	})
	return timescapeConfigManagerInstance
}

// GetTimescapeConfig returns a copy of the current timescape configuration
func (tcm *TimescapeConfigManager) GetTimescapeConfig() *TimescapeConfig {
	tcm.mu.RLock()
	defer tcm.mu.RUnlock()

	if tcm.config == nil {
		return &TimescapeConfig{}
	}

	// Return a copy to prevent external modifications
	return &TimescapeConfig{
		ClientEnabled: tcm.config.ClientEnabled,
		Endpoint:      tcm.config.Endpoint,
		Username:      tcm.config.Username,
		Password:      tcm.config.Password,
	}
}

// SetTimescapeConfig updates the entire timescape configuration
func (tcm *TimescapeConfigManager) SetTimescapeConfig(config *TimescapeConfig) {
	tcm.mu.Lock()
	defer tcm.mu.Unlock()

	if config == nil {
		tcm.config = &TimescapeConfig{}
		return
	}

	tcm.config = &TimescapeConfig{
		ClientEnabled: config.ClientEnabled,
		Endpoint:      config.Endpoint,
		Username:      TIMESCAPE_USERNAME,
		Password:      config.Password,
	}
}

// IsClientEnabled returns whether the timescape client is enabled
func (tcm *TimescapeConfigManager) IsClientEnabled() bool {
	tcm.mu.RLock()
	defer tcm.mu.RUnlock()

	if tcm.config == nil {
		return false
	}
	return tcm.config.ClientEnabled
}

// SetClientEnabled updates the client enabled status
func (tcm *TimescapeConfigManager) SetClientEnabled(enabled bool) {
	tcm.mu.Lock()
	defer tcm.mu.Unlock()

	if tcm.config == nil {
		tcm.config = &TimescapeConfig{}
	}
	tcm.config.ClientEnabled = enabled
}

// Endpoint returns the timescape endpoint URL
func (tcm *TimescapeConfigManager) Endpoint() string {
	tcm.mu.RLock()
	defer tcm.mu.RUnlock()

	if tcm.config == nil {
		return ""
	}
	return tcm.config.Endpoint
}

// SetEndpoint updates the timescape endpoint URL
func (tcm *TimescapeConfigManager) SetEndpoint(endpoint string) {
	tcm.mu.Lock()
	defer tcm.mu.Unlock()

	if tcm.config == nil {
		tcm.config = &TimescapeConfig{}
	}
	tcm.config.Endpoint = endpoint
}

// Username returns the timescape username
func (tcm *TimescapeConfigManager) Username() string {
	tcm.mu.RLock()
	defer tcm.mu.RUnlock()

	if tcm.config == nil {
		return ""
	}
	return tcm.config.Username
}

// SetUsername updates the timescape username
func (tcm *TimescapeConfigManager) SetUsername(username string) {
	tcm.mu.Lock()
	defer tcm.mu.Unlock()

	if tcm.config == nil {
		tcm.config = &TimescapeConfig{}
	}
	tcm.config.Username = username
}

// Password returns the timescape password (use with caution)
func (tcm *TimescapeConfigManager) password() string {
	tcm.mu.RLock()
	defer tcm.mu.RUnlock()

	if tcm.config == nil {
		return ""
	}
	return tcm.config.Password
}

// SetPassword updates the timescape password
func (tcm *TimescapeConfigManager) SetPassword(password string) {
	tcm.mu.Lock()
	defer tcm.mu.Unlock()

	if tcm.config == nil {
		tcm.config = &TimescapeConfig{}
	}
	tcm.config.Password = password
}

// UpdateConfig allows bulk update of multiple configuration fields
func (tcm *TimescapeConfigManager) UpdateConfig(updates map[string]interface{}) {
	tcm.mu.Lock()
	defer tcm.mu.Unlock()

	if tcm.config == nil {
		tcm.config = &TimescapeConfig{}
	}

	for key, value := range updates {
		switch key {
		case "client_enabled":
			if enabled, ok := value.(bool); ok {
				tcm.config.ClientEnabled = enabled
			}
		case "endpoint":
			if endpoint, ok := value.(string); ok {
				tcm.config.Endpoint = endpoint
			}
		case "username":
			if username, ok := value.(string); ok {
				tcm.config.Username = username
			}
		case "password":
			if password, ok := value.(string); ok {
				tcm.config.Password = password
			}
		}
	}
}

// IsConfigured returns true if the essential configuration is present
func (tcm *TimescapeConfigManager) IsConfigured() bool {
	tcm.mu.RLock()
	defer tcm.mu.RUnlock()

	if tcm.config == nil {
		return false
	}

	// Consider configured if client is enabled, password and endpoint are provided
	return tcm.config.ClientEnabled && tcm.config.Endpoint != "" && tcm.config.Password != ""
}

// Package-level convenience functions for easier access
// These functions use the singleton instance

// InitializeTimescapeConfig initializes the singleton with configuration values
func InitializeTimescapeConfig(clientEnabled bool, endpoint, password string) {
	configManager := GetTimescapeConfigManager()
	config := &TimescapeConfig{
		ClientEnabled: clientEnabled,
		Endpoint:      endpoint,
		Username:      TIMESCAPE_USERNAME,
		Password:      password,
	}
	configManager.SetTimescapeConfig(config)
}

// CurrentTimescapeConfig returns the current configuration from singleton
func CurrentTimescapeConfig() *TimescapeConfig {
	return GetTimescapeConfigManager().GetTimescapeConfig()
}

// IsTimescapeClientEnabled checks if timescape client is enabled
func IsTimescapeClientEnabled() bool {
	return GetTimescapeConfigManager().IsClientEnabled()
}

// TimescapeEndpoint returns the current timescape endpoint
func TimescapeEndpoint() string {
	return GetTimescapeConfigManager().Endpoint()
}

// TimescapeUsername returns the current timescape username
func TimescapeUsername() string {
	return GetTimescapeConfigManager().Username()
}

// TimescapePassword returns the current timescape password
func TimescapePassword() string {
	return GetTimescapeConfigManager().password()
}

// GetConfigForDisplay returns configuration safe for display (without password)
func GetConfigForDisplay() map[string]interface{} {
	config := map[string]interface{}{
		"client_status": "Disabled",
		"server_info": map[string]interface{}{
			"endpoint_url": "N/A",
			"username":     "N/A",
			"password":     "N/A",
		},
	}

	tcm := GetTimescapeConfigManager()

	tcm.mu.RLock()
	defer tcm.mu.RUnlock()

	if tcm.config != nil {
		if tcm.config.ClientEnabled {
			config["client_status"] = "Enabled"
		} else {
			config["client_status"] = "Disabled"
		}

		serverInfo, ok := config["server_info"].(map[string]interface{})
		if !ok {
			serverInfo = map[string]interface{}{
				"endpoint_url": "N/A",
				"username":     "N/A",
				"password":     "N/A",
			}
			config["server_info"] = serverInfo
		}
		if tcm.config.Endpoint != "" {
			serverInfo["endpoint_url"] = tcm.config.Endpoint
		}
		if tcm.config.Username != "" {
			serverInfo["username"] = tcm.config.Username
		}

		// Do not reveal whether a password is configured; just indicate that it is not displayed.
		if tcm.config.Password != "" {
			serverInfo["password"] = "[redacted]"
		}
	}

	return config
}
