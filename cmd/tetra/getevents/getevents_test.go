// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package getevents

import (
	"bytes"
	"encoding/json"
	"testing"

	ossTestutils "github.com/cilium/tetragon/pkg/testutils"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/testutils"
)

func Test_GetEvents_Namespace(t *testing.T) {
	t.Run("FilterNothing", func(t *testing.T) {
		ossTestutils.MockPipedFile(t, testutils.RepoRootPath("testdata/recorder/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--namespaces", "demo-app"})
		output := ossTestutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 100, bytes.Count(output, []byte("\n")))
	})

	t.Run("FilterAll", func(t *testing.T) {
		ossTestutils.MockPipedFile(t, testutils.RepoRootPath("testdata/recorder/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--namespaces", "doesnotexist"})
		output := ossTestutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 0, bytes.Count(output, []byte("\n")))
	})
}

func Test_GetEvents_Pod(t *testing.T) {
	t.Run("FilterCoreapi", func(t *testing.T) {
		ossTestutils.MockPipedFile(t, testutils.RepoRootPath("testdata/recorder/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--pods", "coreapi"})
		output := ossTestutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 18, bytes.Count(output, []byte("\n")))
	})

	t.Run("FilterLoader", func(t *testing.T) {
		ossTestutils.MockPipedFile(t, testutils.RepoRootPath("testdata/recorder/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--pods", "loader"})
		output := ossTestutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 82, bytes.Count(output, []byte("\n")))
	})

	t.Run("FilterAll", func(t *testing.T) {
		ossTestutils.MockPipedFile(t, testutils.RepoRootPath("testdata/recorder/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--pods", "doesnotexist"})
		output := ossTestutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 0, bytes.Count(output, []byte("\n")))
	})
}

func Test_GetEvents_Process(t *testing.T) {
	t.Run("FilterPythonNode", func(t *testing.T) {
		ossTestutils.MockPipedFile(t, testutils.RepoRootPath("testdata/recorder/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--processes", "python,node"})
		output := ossTestutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 74, bytes.Count(output, []byte("\n")))
	})

	t.Run("FilterAll", func(t *testing.T) {
		ossTestutils.MockPipedFile(t, testutils.RepoRootPath("testdata/recorder/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--processes", "doesnotexist"})
		output := ossTestutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 0, bytes.Count(output, []byte("\n")))
	})
}

func Test_GetEvents_IPCIDR(t *testing.T) {
	t.Run("FilterEventsWithIPs", func(t *testing.T) {
		ossTestutils.MockPipedFile(t, testutils.RepoRootPath("testdata/recorder/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--ip-cidr", "0.0.0.0/0"})
		output := ossTestutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 72, bytes.Count(output, []byte("\n")))
	})

	t.Run("FilterEventsSpecificIPs", func(t *testing.T) {
		ossTestutils.MockPipedFile(t, testutils.RepoRootPath("testdata/recorder/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--ip-cidr", "10.244.0.204/32"})
		output := ossTestutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 4, bytes.Count(output, []byte("\n")))
	})
}

func Test_GetEvents_DestIPCIDR(t *testing.T) {
	t.Run("FilterEventsNonExistingIPs", func(t *testing.T) {
		ossTestutils.MockPipedFile(t, testutils.RepoRootPath("testdata/recorder/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--dest-ip-cidr", "10.10.10.10/32"})
		output := ossTestutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 0, bytes.Count(output, []byte("\n")))
	})

	t.Run("FilterEventsSpecificIPs", func(t *testing.T) {
		ossTestutils.MockPipedFile(t, testutils.RepoRootPath("testdata/recorder/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--dest-ip-cidr", "10.96.0.10/32"})
		output := ossTestutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 71, bytes.Count(output, []byte("\n")))
	})
}

func Test_GetEvents_SourceIPCIDR(t *testing.T) {
	t.Run("FilterEventsNonExistingIPs", func(t *testing.T) {
		ossTestutils.MockPipedFile(t, testutils.RepoRootPath("testdata/recorder/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--source-ip-cidr", "10.10.10.10/32"})
		output := ossTestutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 0, bytes.Count(output, []byte("\n")))
	})

	t.Run("FilterEventsSpecificIPs", func(t *testing.T) {
		ossTestutils.MockPipedFile(t, testutils.RepoRootPath("testdata/recorder/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--source-ip-cidr", "10.244.0.204/32"})
		output := ossTestutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 4, bytes.Count(output, []byte("\n")))
	})
}

func Test_GetEvents_FilterFields(t *testing.T) {
	t.Run("ExcludeParent", func(t *testing.T) {
		ossTestutils.MockPipedFile(t, testutils.RepoRootPath("testdata/recorder/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"-F", "parent"})
		output := ossTestutils.RedirectStdoutExecuteCmd(t, cmd)
		// remove last trailing newline for splitting
		output = bytes.TrimSpace(output)
		lines := bytes.Split(output, []byte("\n"))
		for _, line := range lines {
			var res tetragon.GetEventsResponse
			err := json.Unmarshal(line, &res)
			if err != nil {
				t.Fatal(err)
			}
			if ev, ok := tetragon.UnwrapGetEventsResponse(&res).(interface {
				GetProcess() *tetragon.Process
				GetParent() *tetragon.Process
			}); ok {
				assert.NotEmpty(t, ev.GetProcess())
				assert.Empty(t, ev.GetParent())
			}
		}
	})

	t.Run("IncludeParent", func(t *testing.T) {
		ossTestutils.MockPipedFile(t, testutils.RepoRootPath("testdata/recorder/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"-f", "parent"})
		output := ossTestutils.RedirectStdoutExecuteCmd(t, cmd)
		// remove last trailing newline for splitting
		output = bytes.TrimSpace(output)
		lines := bytes.Split(output, []byte("\n"))
		for _, line := range lines {
			var res tetragon.GetEventsResponse
			err := json.Unmarshal(line, &res)
			if err != nil {
				t.Fatal(err)
			}
			if ev, ok := tetragon.UnwrapGetEventsResponse(&res).(interface {
				GetProcess() *tetragon.Process
				GetParent() *tetragon.Process
			}); ok {
				// exception because the JSON is outdated
				if _, ok := ev.(*tetragon.ProcessDns); !ok {
					continue
				}
				// exception because the JSON is outdated
				if _, ok := ev.(*tetragon.ProcessSockStats); !ok {
					continue
				}
				assert.NotEmpty(t, ev.GetParent())
				assert.Empty(t, ev.GetProcess())
			}
		}
	})
}
