// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.
//

//go:build sudo_tests

package layer3_test

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	osstestutils "github.com/cilium/tetragon/pkg/testutils"

	pb "github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	cli "github.com/isovalent/hubble-fgs/pkg/testutils/cliswitches"
	enterprisepolicytest "github.com/isovalent/hubble-fgs/pkg/testutils/policytest"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
	_ "github.com/isovalent/hubble-fgs/tests/policytests"
)

// IGMP has some characteristics that make test order important.
// For these tests we do not wish to use loopback or virtual interfaces as they
// are liable to behave differently to "real" interfaces.
// But IGMP has (currently) three versions, and the protocol version it chooses
// to respond to a query is dependent on the protocol versions observed on the
// interface. If V2 has been seen recently, then responses will be V2, otherwise
// they will be V3 (assuming V3 was used to set up the group joins).
//
// golang tests are run in the order they are declared. testify suite tests,
// that run within a golang test, are run in alphabetical order (technically
// the order returned by reflect but this is unlikely to change). To force the
// V3 tests to precede the V2 tests, we either need creative test naming, or
// we simply need a V3 suite that runs before a V2 suite. We have implemented
// the latter.

// It is important the V3 tests precede the V2 tests. See above for a discussion.
func TestIGMPV3(t *testing.T) {
	if !kernels.MinKernelVersion("6.6") {
		t.Skipf("This test requires kernel v6.6 or later, skipping")
	}
	suite.Run(t, new(IGMPV3))
}

// It is important the V3 tests precede the V2 tests. See above for a discussion.
func TestIGMPV2(t *testing.T) {
	if !kernels.MinKernelVersion("5.15") {
		t.Skipf("This test requires kernel v5.15 or later, skipping")
	}
	enterprisepolicytest.DoObserverTestUnfiltered(t, "layer3-igmp-v2-lifecycle", nil)
}

type IGMPV3 struct {
	suite.Suite
	switches        []cli.SwitchSettings
	doneWG, readyWG sync.WaitGroup
	ctx             context.Context
	cancel          context.CancelFunc
}

func (suite *IGMPV3) SetupSuite() {
	suite.ctx, suite.cancel = context.WithTimeout(context.Background(), runner.Conf().CmdWaitTime)
	var err error
	suite.switches, err = cli.SetConfigFromSwitches([]cli.SwitchSettings{
		{KeyPtr: &enterpriseOption.Config.Layer3CLIEnable, Value: true},
		{KeyPtr: &enterpriseOption.Config.EnableNetworkEvents, Value: true},
		{KeyPtr: &enterpriseOption.Config.EnableTCP, Value: true},
		{KeyPtr: &enterpriseOption.Config.EnableUDP, Value: true},
		{KeyPtr: &enterpriseOption.Config.EnableUserDNS, Value: true},
		{KeyPtr: &enterpriseOption.Config.EnableIGMP, Value: true},
	})
	suite.Require().NoError(err)

	obs := enterpriseoth.GetNoConfigObserver(suite.T(), suite.ctx, false)
	suite.Require().NoError(layer3.StartLayer3Progs(suite.ctx, nil))
	observertesthelper.LoopEvents(suite.ctx, suite.T(), &suite.doneWG, &suite.readyWG, obs)
}

func (suite *IGMPV3) HandleStats(_ string, stats *suite.SuiteInformation) {
	if stats.Passed() {
		osstestutils.DoneWithExportFile(suite.T())
	}
}

func (suite *IGMPV3) TearDownSuite() {
	suite.cancel()
	cli.RevertSwitchesConfig(suite.switches)
}

func (suite *IGMPV3) TestIGMPJoinAndReport() {
	if !kernels.MinKernelVersion("6.6.0") {
		suite.T().Skip("Test requires kernel >=6.6")
	}

	cmd := "/usr/bin/socat"
	groupAddr := "224.3.3.3"
	defaultRoute, err := exec.Command("bash", "-c", "ip r | grep default").Output()
	suite.Require().NoError(err)
	defaultRouteFields := strings.Fields(string(defaultRoute))
	ifName := defaultRouteFields[4]
	ifAddr := defaultRouteFields[8]
	igmpquery := testutils.RepoRootPath("contrib/tester-progs/net/igmpquery")
	suite.T().Logf("igmpquery = '%s'", igmpquery)

	selfChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(runner.Conf().SelfBinary))

	socatChecker := ec.NewProcessChecker().
		WithBinary(sm.Suffix(cmd)).
		WithArguments(sm.Full(fmt.Sprintf("- UDP4-LISTEN:6858,ip-add-membership=%s:%s,fork", groupAddr, ifAddr)))

	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("selfExec").
			WithProcess(selfChecker).
			WithParent(ec.NewProcessChecker()),
		ec.NewProcessExecChecker("socatExec").
			WithProcess(socatChecker).
			WithParent(selfChecker),
		ec.NewProcessIgmpJoinChecker("IGMPJoin").
			WithProcess(socatChecker).
			WithParent(selfChecker).
			WithInterfaceName(sm.Full(ifName)).
			WithSourceIp(sm.Full(ifAddr)).
			WithGroupIp(sm.Full(groupAddr)),
		ec.NewIgmpMembershipReportChecker("IGMPReport").
			WithType(pb.IgmpMembershipReportType_IGMPV3_HOST_MEMBERSHIP_REPORT).
			WithSourceIp(sm.Full(ifAddr)).
			WithGroupIp(sm.Full("224.0.0.22")).
			WithInterfaceName(sm.Full(ifName)).
			WithGroups(ec.NewIgmpGroupRecordListMatcher().
				WithValues(ec.NewIgmpGroupRecordChecker().
					WithGroupIp(sm.Full(groupAddr)))),
	)

	suite.readyWG.Wait()
	cmdServer := exec.Command(cmd, "-", fmt.Sprintf("UDP4-LISTEN:6858,ip-add-membership=%s:%s,fork", groupAddr, ifAddr))
	require.NoError(suite.T(), cmdServer.Start())
	defer killAndWaitCommand(suite.T(), cmdServer)
	err = waitForSocketToListen(suite.T(), net.ParseIP("0.0.0.0"), 6858, syscall.IPPROTO_UDP, syscall.AF_INET)
	require.NoError(suite.T(), err)

	igmpqueryOutput, err := exec.Command(igmpquery, "3", ifName).CombinedOutput()
	if err != nil {
		suite.T().Logf("igmpquery output:\n%s\n", string(igmpqueryOutput))
	}
	require.NoError(suite.T(), err)

	err = jsonchecker.JsonTestCheckExpectWithKeep(suite.T(), checker, false, true)
	require.NoError(suite.T(), err)
}
