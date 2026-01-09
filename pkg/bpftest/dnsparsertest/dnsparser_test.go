// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build sudo_tests

package dnsparsertest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/bpftest"
	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	"github.com/isovalent/hubble-fgs/pkg/option"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

func TestDNSParserPerPodFeature(t *testing.T) {
	if !utils.SupportDNSParser() || !utils.SockopsSupportsCgroupAncestorHelper() {
		t.Skip()
	}

	option.Config.EnableBPFDNSPerPod = true
	option.Config.BPFDNSPerPodPrealloc = 6
	option.Config.BPFDNSPerPodThresold = 2
	arbitraryCgroupID := uint64(666)
	dnsparser.GetKubepodsSliceCgroupID = func() (uint64, error) {
		return arbitraryCgroupID, nil
	}
	bpftest.StartMinimalTetragonModel(context.Background(), t)

	// check that at least the pre-allocated map are pinned
	for index := range option.Config.BPFDNSPerPodPrealloc {
		_, err := os.Stat(filepath.Join(bpf.MapPrefixPath(), fmt.Sprintf("%s_%d", dnsparser.IPToIDMapsName, index)))
		require.NoError(t, err, "map should have been pre-allocated and pinned")
	}

	// check that consts have been rewritten (and thus program should load and pass the verifier)
	// this is not super solid and might break but we need at least a test that loads this feature
	cmdArgs := []string{"--json", "map", "dump", "name", ".rodata"}
	cmd := exec.Command("bpftool", cmdArgs...)
	output, err := cmd.Output()
	require.NoError(t, err)
	outputString := string(output)

	assert.Contains(t, outputString, fmt.Sprintf("\"%s\":1", dnsparser.ParserEnabledName))
	assert.Contains(t, outputString, fmt.Sprintf("\"%s\":1", dnsparser.PerPodFeatureName))
	assert.Contains(t, outputString, fmt.Sprintf("\"%s\":%d", dnsparser.KubepodsCgidConstName, arbitraryCgroupID))
}
