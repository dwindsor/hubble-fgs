// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package option

import (
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_validateConfig(t *testing.T) {
	c := Config
	c.Environment = "bad-env"
	err := validateConfig(c)
	assert.EqualError(t, err, "invalid environment 'bad-env', valid values are [aws azure gcloud kubernetes]")
	c.Environment = EnvironmentKubernetes
	assert.NoError(t, validateConfig(c))
}

func Test_validateConfigSplunkHEC(t *testing.T) {
	c := Config

	c.SplunkHECEndpoint, _ = url.Parse("https://splunk.example.com:8088/services/collector")
	c.SplunkHECToken = ""
	assert.EqualError(t, validateConfig(c), "--splunk-hec-endpoint and --splunk-hec-token must be set together")

	c.SplunkHECEndpoint = nil
	c.SplunkHECToken = "some-token"
	assert.EqualError(t, validateConfig(c), "--splunk-hec-endpoint and --splunk-hec-token must be set together")

	c.SplunkHECEndpoint, _ = url.Parse("https://splunk.example.com:8088/services/collector")
	assert.NoError(t, validateConfig(c))

	c.SplunkHECEndpoint = nil
	c.SplunkHECToken = ""
	assert.NoError(t, validateConfig(c))
}

func Test_validateConfigSplunkHECMaxContentLength(t *testing.T) {
	c := Config
	c.Environment = EnvironmentKubernetes

	for _, length := range []int{0, 1, splunkHECMinContentLength} {
		c.SplunkHECMaxContentLength = length
		assert.EqualError(t, validateConfig(c), "--splunk-hec-max-content-length must be greater than "+strconv.Itoa(splunkHECMinContentLength)+" bytes")
	}

	c.SplunkHECMaxContentLength = splunkHECMinContentLength + 1
	assert.NoError(t, validateConfig(c))
}

func Test_validateConfigSplunkHECDurations(t *testing.T) {
	c := Config
	c.Environment = EnvironmentKubernetes
	for _, d := range []time.Duration{-time.Second, 0, splunkHECMinFlushInterval - time.Millisecond} {
		c.SplunkHECFlushInterval = d
		assert.EqualError(t, validateConfig(c), "--splunk-hec-flush-interval must be at least "+splunkHECMinFlushInterval.String())
	}
	c.SplunkHECFlushInterval = splunkHECMinFlushInterval
	assert.NoError(t, validateConfig(c))

	c = Config
	c.Environment = EnvironmentKubernetes
	for _, d := range []time.Duration{-time.Second, 0, splunkHECMinTimeout - time.Millisecond} {
		c.SplunkHECTimeout = d
		assert.EqualError(t, validateConfig(c), "--splunk-hec-timeout must be at least "+splunkHECMinTimeout.String())
	}
	c.SplunkHECTimeout = splunkHECMinTimeout
	assert.NoError(t, validateConfig(c))
}

func Test_validateConfigSplunkHECSourcetypes(t *testing.T) {
	c := Config
	c.Environment = EnvironmentKubernetes
	c.SplunkHECSourcetypes = append([]string(nil), splunkHECValidSourcetypes...)
	assert.NoError(t, validateConfig(c))

	c.SplunkHECSourcetypes = []string{SplunkHECSourcetypeEvents, "tetragon:not-real"}
	assert.EqualError(t, validateConfig(c), "invalid value for --splunk-hec-sourcetypes: \"tetragon:not-real\" is not a valid sourcetype, valid values are [tetragon:events tetragon:flows tetragon:ocsf tetragon:application_model tetragon:telemetry tetragon:connections tetragon:alerts]")
}

func TestParseAdditionalNodeLabels(t *testing.T) {
	labels, err := parseAdditionalNodeLabels([]string{"zone=us-east-1a", "role=worker"})
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"zone": "us-east-1a", "role": "worker"}, labels)
}

func TestParseAdditionalNodeLabelsDuplicateKey(t *testing.T) {
	_, err := parseAdditionalNodeLabels([]string{"zone=us-east-1a", "zone=us-east-1b"})
	assert.EqualError(t, err, "duplicate --additional-node-label key \"zone\"")
}

func TestParseAdditionalNodeLabelsInvalidValue(t *testing.T) {
	_, err := parseAdditionalNodeLabels([]string{"zone"})
	assert.EqualError(t, err, "--additional-node-label must be specified as key=value")
}
