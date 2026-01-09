// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package loadconfig

import (
	"os"
	"testing"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/fwactl"
)

func TestRunE(t *testing.T) {
	// Test missing filepath
	cmd := &cobra.Command{}
	err := loadconfigCmd.RunE(cmd, []string{})
	if err == nil || err.Error() != "missing filepath" {
		t.Errorf("Expected missing filepath error, got: %v", err)
	}

	cfgFile, err := os.CreateTemp("", "*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	fwactl.CONFIG = cfgFile.Name()
	os.Remove(cfgFile.Name())
	tmpFile, err := os.CreateTemp("", "*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.WriteString("{}")
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	err = loadconfigCmd.RunE(cmd, []string{tmpFile.Name()})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	defer os.Remove(fwactl.CONFIG)
	if _, err := os.Stat(fwactl.CONFIG); os.IsNotExist(err) {
		t.Fatalf("commands.CONFIG file does not exist")
	}
}
