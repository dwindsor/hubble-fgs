// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package ha

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHaCmd(t *testing.T) {
	assert.Equal(t, "ha", HaCmd.Use)
	assert.True(t, HaCmd.SilenceUsage)
}

func TestHaShowCmd(t *testing.T) {
	var found bool
	for _, cmd := range HaCmd.Commands() {
		if cmd.Use == "show" {
			found = true
			assert.NotNil(t, cmd.RunE)
			break
		}
	}
	assert.True(t, found, "show subcommand not registered")
}

func TestHaInfoCmd(t *testing.T) {
	var found bool
	for _, cmd := range HaCmd.Commands() {
		if cmd.Use == "info" {
			found = true
			assert.NotNil(t, cmd.RunE)
			break
		}
	}
	assert.True(t, found, "info subcommand not registered")
}
