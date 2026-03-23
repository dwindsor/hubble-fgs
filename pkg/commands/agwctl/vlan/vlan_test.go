// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package vlan

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVlanCmd(t *testing.T) {
	assert.Equal(t, "vlan", VlanCmd.Use)
	assert.True(t, VlanCmd.SilenceUsage)
}

func TestVlanShowCmd(t *testing.T) {
	var found bool
	for _, cmd := range VlanCmd.Commands() {
		if cmd.Use == "show" {
			found = true
			assert.NotNil(t, cmd.RunE)
			assert.NotNil(t, cmd.Flags().Lookup("filter"), "show should have --filter flag")
			break
		}
	}
	assert.True(t, found, "show subcommand not registered")
}

func TestVlanListCmd(t *testing.T) {
	var found bool
	for _, cmd := range VlanCmd.Commands() {
		if cmd.Use == "list" {
			found = true
			assert.NotNil(t, cmd.RunE)
			break
		}
	}
	assert.True(t, found, "list subcommand not registered")
}

func TestVlanInfoCmd(t *testing.T) {
	var found bool
	for _, cmd := range VlanCmd.Commands() {
		if cmd.Use == "info" {
			found = true
			assert.NotNil(t, cmd.RunE)
			break
		}
	}
	assert.True(t, found, "info subcommand not registered")
}
