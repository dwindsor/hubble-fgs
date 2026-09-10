// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package hec

import (
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
)

type Config struct {
	SplunkHECEndpoint         *url.URL
	SplunkHECToken            string
	SplunkHECMaxContentLength int
	SplunkHECFlushInterval    time.Duration
	SplunkHECTimeout          time.Duration
	SplunkHECSourcetypes      []string
	EnableSplunkHECDebug      bool
}

var config atomic.Pointer[Config]

// Initialize config from command line options
func initConfig() {
	initial := &Config{
		SplunkHECEndpoint:         enterpriseOption.Config.SplunkHECEndpoint,
		SplunkHECToken:            enterpriseOption.Config.SplunkHECToken,
		SplunkHECMaxContentLength: enterpriseOption.Config.SplunkHECMaxContentLength,
		SplunkHECFlushInterval:    enterpriseOption.Config.SplunkHECFlushInterval,
		SplunkHECTimeout:          enterpriseOption.Config.SplunkHECTimeout,
		SplunkHECSourcetypes:      append([]string{}, enterpriseOption.Config.SplunkHECSourcetypes...),
		EnableSplunkHECDebug:      enterpriseOption.Config.EnableSplunkHECDebug,
	}
	config.Store(initial)
}

// Get the current config, which may have been modified via SetHecSettings()
func GetConfig() *atomic.Pointer[Config] {
	var once sync.Once
	once.Do(initConfig)
	return &config
}

func (c *Config) shouldWrite(sourcetype string) bool {
	return c.SplunkHECEndpoint != nil && c.SplunkHECEndpoint.String() != "" && slices.Contains(c.SplunkHECSourcetypes, sourcetype)
}
