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
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_validateConfig(t *testing.T) {
	Config.Environment = "bad-env"
	err := validateConfig(Config)
	assert.EqualError(t, err, "invalid environment 'bad-env', valid values are [aws azure gcloud kubernetes]")
	Config.Environment = EnvironmentKubernetes
	assert.NoError(t, validateConfig(Config))
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
