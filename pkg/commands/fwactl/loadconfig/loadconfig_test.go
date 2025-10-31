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
