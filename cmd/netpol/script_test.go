package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
)

func TestScript(t *testing.T) {
	// Override the error&exit to gracefully catch it.
	commandFailed := false
	printErrorAndExit = func(f string, args ...any) {
		t.Logf(f, args...)
		commandFailed = true
	}

	scripttest.Test(
		t,
		t.Context(),
		func(tb testing.TB, args []string) *script.Engine {
			e := script.NewEngine()
			e.Cmds["netpol"] = script.Command(
				script.CmdUsage{},
				func(s *script.State, args ...string) (script.WaitFunc, error) {
					oldDir, _ := os.Getwd()
					os.Chdir(s.Getwd())
					defer os.Chdir(oldDir)
					rootCmd.SetArgs(args)
					commandFailed = false
					if err := rootCmd.Execute(); err != nil {
						return nil, err
					}
					if commandFailed {
						return nil, fmt.Errorf("command failed")
					}
					return nil, nil
				},
			)
			return e
		},
		nil,
		"testdata/*.txtar",
		scripttest.NoParallel,
	)
}
