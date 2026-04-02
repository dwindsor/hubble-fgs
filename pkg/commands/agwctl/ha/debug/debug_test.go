// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package debug

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDebugCmd(t *testing.T) {
	assert.Equal(t, "debug", DebugCmd.Use)
	assert.True(t, DebugCmd.SilenceUsage)
}

func TestDebugFailCmd(t *testing.T) {
	var found bool
	for _, cmd := range DebugCmd.Commands() {
		if cmd.Use == "fail" {
			found = true
			assert.NotNil(t, cmd.RunE)
			break
		}
	}
	assert.True(t, found, "fail subcommand not registered")
}

func TestDebugOkCmd(t *testing.T) {
	var found bool
	for _, cmd := range DebugCmd.Commands() {
		if cmd.Use == "ok" {
			found = true
			assert.NotNil(t, cmd.RunE)
			break
		}
	}
	assert.True(t, found, "ok subcommand not registered")
}

func TestDebugPeerFailCmd(t *testing.T) {
	var found bool
	for _, cmd := range DebugCmd.Commands() {
		if cmd.Use == "peer-fail" {
			found = true
			assert.NotNil(t, cmd.RunE)
			assert.NotNil(t, cmd.Flags().Lookup("peer"), "peer-fail should have --peer flag")
			assert.NotNil(t, cmd.Flags().Lookup("membership"), "peer-fail should have --membership flag")
			assert.NotNil(t, cmd.Flags().Lookup("adjacency"), "peer-fail should have --adjacency flag")
			break
		}
	}
	assert.True(t, found, "peer-fail subcommand not registered")
}

func TestDebugPeerOkCmd(t *testing.T) {
	var found bool
	for _, cmd := range DebugCmd.Commands() {
		if cmd.Use == "peer-ok" {
			found = true
			assert.NotNil(t, cmd.RunE)
			assert.NotNil(t, cmd.Flags().Lookup("peer"), "peer-ok should have --peer flag")
			assert.NotNil(t, cmd.Flags().Lookup("membership"), "peer-ok should have --membership flag")
			assert.NotNil(t, cmd.Flags().Lookup("adjacency"), "peer-ok should have --adjacency flag")
			break
		}
	}
	assert.True(t, found, "peer-ok subcommand not registered")
}
