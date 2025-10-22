package loadconfig

import (
	"net"
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

	// Test successful run - skip if DPU interface doesn't exist (e.g., in CI)
	intfs, err := net.Interfaces()
	if err != nil {
		t.Skipf("Cannot get network interfaces: %v", err)
	}
	hasInterface := false
	for _, intf := range intfs {
		if intf.Name == "int_mnic0" {
			hasInterface = true
			break
		}
	}
	if !hasInterface {
		t.Skip("Skipping test: int_mnic0 interface not found (not on DPU hardware)")
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
