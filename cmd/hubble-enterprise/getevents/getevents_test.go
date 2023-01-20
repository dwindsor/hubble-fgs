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
	"testing"

	ossTestutils "github.com/cilium/tetragon/pkg/testutils"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	"github.com/stretchr/testify/assert"
)

func Test_GetEvents_Namespace(t *testing.T) {
	t.Run("FilterNothing", func(t *testing.T) {
		ossTestutils.MockPipedFile(t, testutils.RepoRootPath("testdata/recorder/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--namespace", "demo-app"})
		output := ossTestutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 100, bytes.Count(output, []byte("\n")))
	})

	t.Run("FilterAll", func(t *testing.T) {
		ossTestutils.MockPipedFile(t, testutils.RepoRootPath("testdata/recorder/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--namespace", "doesnotexist"})
		output := ossTestutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 0, bytes.Count(output, []byte("\n")))
	})
}

func Test_GetEvents_Pod(t *testing.T) {
	t.Run("FilterCoreapi", func(t *testing.T) {
		ossTestutils.MockPipedFile(t, testutils.RepoRootPath("testdata/recorder/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--pod", "coreapi"})
		output := ossTestutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 18, bytes.Count(output, []byte("\n")))
	})

	t.Run("FilterLoader", func(t *testing.T) {
		ossTestutils.MockPipedFile(t, testutils.RepoRootPath("testdata/recorder/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--pod", "loader"})
		output := ossTestutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 82, bytes.Count(output, []byte("\n")))
	})

	t.Run("FilterAll", func(t *testing.T) {
		ossTestutils.MockPipedFile(t, testutils.RepoRootPath("testdata/recorder/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--pod", "doesnotexist"})
		output := ossTestutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 0, bytes.Count(output, []byte("\n")))
	})
}

func Test_GetEvents_Process(t *testing.T) {
	t.Run("FilterPythonNode", func(t *testing.T) {
		ossTestutils.MockPipedFile(t, testutils.RepoRootPath("testdata/recorder/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--process", "python,node"})
		output := ossTestutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 74, bytes.Count(output, []byte("\n")))
	})

	t.Run("FilterAll", func(t *testing.T) {
		ossTestutils.MockPipedFile(t, testutils.RepoRootPath("testdata/recorder/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--process", "doesnotexist"})
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
