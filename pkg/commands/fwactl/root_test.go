package fwactl

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
)

func TestRootCmd(t *testing.T) {
	// Test version flag
	args := []string{"--version"}
	RootCmd.SetArgs(args)
	err := RootCmd.Execute()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Test JSON flag
	args = []string{"--json"}
	RootCmd.SetArgs(args)
	err = RootCmd.Execute()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !JSON {
		t.Errorf("Expected JSON to be true")
	}
}

func TestPersistentPreRunE(t *testing.T) {
	cmd := &cobra.Command{
		Annotations: map[string]string{"command": "loadconfig"},
	}
	err := RootCmd.PersistentPreRunE(cmd, []string{})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	cmd = &cobra.Command{}
	err = RootCmd.PersistentPreRunE(cmd, []string{})
	if err == nil || err.Error() != "fwactl config file not found, please run loadconfig" {
		t.Errorf("Expected config file not found error, got: %v", err)
	}

	tmpFile, err := os.CreateTemp("", "fwactl.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	CONFIG_LIST = append(CONFIG_LIST, tmpFile.Name())

	err = RootCmd.PersistentPreRunE(cmd, []string{})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}
