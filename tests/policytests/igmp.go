// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !windows

package tests

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/kernels"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/testutils/policytest"

	"github.com/isovalent/hubble-fgs/pkg/testutils/policytestconfig"
)

type igmpTrigger struct {
	socatPath       string
	queryPath       string
	interfaceName   string
	interfaceAddr   string
	groupAddr       string
	port            int
	query           bool
	stopBeforeCheck bool
}

func defaultInterface() (string, string, error) {
	defaultRoute, err := exec.Command("bash", "-c", "ip r | grep default").Output()
	if err != nil {
		return "", "", err
	}
	defaultRouteFields := strings.Fields(string(defaultRoute))
	return defaultRouteFields[4], defaultRouteFields[8], nil
}

func (trigger *igmpTrigger) Trigger(ctx context.Context) error {
	socatArgument := fmt.Sprintf("UDP4-LISTEN:%d,ip-add-membership=%s:%s,fork", trigger.port, trigger.groupAddr, trigger.interfaceAddr)
	server := exec.CommandContext(ctx, trigger.socatPath, "-", socatArgument)
	server.Stdout = os.Stderr
	server.Stderr = os.Stderr
	if err := server.Start(); err != nil {
		return err
	}
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.Wait()
	}()

	if err := waitForSocketToListen(ctx, net.ParseIP("0.0.0.0"), uint16(trigger.port), syscall.IPPROTO_UDP, syscall.AF_INET); err != nil {
		return err
	}
	if trigger.query {
		queryOutput, queryErr := exec.CommandContext(ctx, trigger.queryPath, "2", trigger.interfaceName).CombinedOutput()
		if queryErr != nil {
			return fmt.Errorf("IGMP query failed: %w: %s", queryErr, queryOutput)
		}
	}
	if trigger.stopBeforeCheck {
		if err := server.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		if err := <-serverDone; err != nil {
			if _, ok := err.(*exec.ExitError); !ok {
				return err
			}
		}
	}
	return nil
}

var _ = policytest.NewBuilder("layer3-igmp-v2-lifecycle").
	WithLabels("layer3", "igmp").
	WithCLIFlags(
		policytest.CLIFlag{Name: "enable-network-events", Value: true},
		policytest.CLIFlag{Name: "enable-tcp", Value: true},
		policytest.CLIFlag{Name: "enable-udp", Value: true},
		policytest.CLIFlag{Name: "enable-user-dns", Value: true},
		policytest.CLIFlag{Name: "enable-igmp", Value: true},
	).
	WithSkip(func(_ *policytest.SkipInfo) string {
		if !kernels.MinKernelVersion("5.15") {
			return "test requires kernel >=5.15"
		}
		return ""
	}).
	WithPolicyTemplate(emptyTracingPolicy).
	AddScenario(func(_ *policytest.Conf) *policytest.Scenario {
		socatPath := "/usr/bin/socat"
		interfaceName, interfaceAddr, err := defaultInterface()
		if err != nil {
			panic(err)
		}
		groupAddr := "224.1.1.1"
		selfChecker := ec.NewProcessChecker().
			WithBinary(sm.Suffix(filepath.Base(os.Args[0])))
		socatChecker := ec.NewProcessChecker().
			WithBinary(sm.Suffix(filepath.Base(socatPath))).
			WithArguments(sm.Full(fmt.Sprintf("- UDP4-LISTEN:6858,ip-add-membership=%s:%s,fork", groupAddr, interfaceAddr)))
		return &policytest.Scenario{
			Name: "IGMPv2 join",
			Trigger: &igmpTrigger{
				socatPath:     socatPath,
				interfaceName: interfaceName, interfaceAddr: interfaceAddr,
				groupAddr: groupAddr, port: 6858,
			},
			EventChecker: ec.NewUnorderedEventChecker(
				ec.NewProcessExecChecker("socatExec").
					WithProcess(socatChecker).
					WithParent(selfChecker),
				ec.NewProcessIgmpJoinChecker("igmpJoin").
					WithProcess(socatChecker).
					WithParent(selfChecker).
					WithInterfaceName(sm.Full(interfaceName)).
					WithSourceIp(sm.Full(interfaceAddr)).
					WithGroupIp(sm.Full(groupAddr)),
			),
		}
	}).
	AddScenario(func(_ *policytest.Conf) *policytest.Scenario {
		socatPath := "/usr/bin/socat"
		queryPath := policytestconfig.EnterpriseTestBinary("net/igmpquery")
		interfaceName, interfaceAddr, err := defaultInterface()
		if err != nil {
			panic(err)
		}
		groupAddr := "224.2.2.2"
		selfChecker := ec.NewProcessChecker().
			WithBinary(sm.Suffix(filepath.Base(os.Args[0])))
		socatChecker := ec.NewProcessChecker().
			WithBinary(sm.Suffix(filepath.Base(socatPath))).
			WithArguments(sm.Full(fmt.Sprintf("- UDP4-LISTEN:6858,ip-add-membership=%s:%s,fork", groupAddr, interfaceAddr)))
		return &policytest.Scenario{
			Name: "IGMPv2 membership report",
			Trigger: &igmpTrigger{
				socatPath: socatPath, queryPath: queryPath,
				interfaceName: interfaceName, interfaceAddr: interfaceAddr,
				groupAddr: groupAddr, port: 6858, query: true,
			},
			EventChecker: ec.NewUnorderedEventChecker(
				ec.NewProcessExecChecker("socatExec").
					WithProcess(socatChecker).
					WithParent(selfChecker),
				ec.NewProcessIgmpJoinChecker("igmpJoin").
					WithProcess(socatChecker).
					WithParent(selfChecker).
					WithInterfaceName(sm.Full(interfaceName)).
					WithSourceIp(sm.Full(interfaceAddr)).
					WithGroupIp(sm.Full(groupAddr)),
				ec.NewIgmpMembershipReportChecker("igmpReport").
					WithType(tetragon.IgmpMembershipReportType_IGMPV2_HOST_MEMBERSHIP_REPORT).
					WithSourceIp(sm.Full(interfaceAddr)).
					WithGroupIp(sm.Full(groupAddr)).
					WithInterfaceName(sm.Full(interfaceName)),
			),
		}
	}).
	AddScenario(func(_ *policytest.Conf) *policytest.Scenario {
		socatPath := "/usr/bin/socat"
		interfaceName, interfaceAddr, err := defaultInterface()
		if err != nil {
			panic(err)
		}
		groupAddr := "224.2.2.2"
		selfChecker := ec.NewProcessChecker().
			WithBinary(sm.Suffix(filepath.Base(os.Args[0])))
		socatChecker := ec.NewProcessChecker().
			WithBinary(sm.Suffix(filepath.Base(socatPath))).
			WithArguments(sm.Full(fmt.Sprintf("- UDP4-LISTEN:6858,ip-add-membership=%s:%s,fork", groupAddr, interfaceAddr)))
		return &policytest.Scenario{
			Name: "IGMPv2 leave",
			Trigger: &igmpTrigger{
				socatPath:     socatPath,
				interfaceName: interfaceName, interfaceAddr: interfaceAddr,
				groupAddr: groupAddr, port: 6858, stopBeforeCheck: true,
			},
			EventChecker: ec.NewUnorderedEventChecker(
				ec.NewProcessExecChecker("socatExec").
					WithProcess(socatChecker).
					WithParent(selfChecker),
				ec.NewProcessIgmpJoinChecker("igmpJoin").
					WithProcess(socatChecker).
					WithParent(selfChecker).
					WithInterfaceName(sm.Full(interfaceName)).
					WithSourceIp(sm.Full(interfaceAddr)).
					WithGroupIp(sm.Full(groupAddr)),
				ec.NewIgmpMembershipReportChecker("igmpLeave").
					WithType(tetragon.IgmpMembershipReportType_IGMP_HOST_LEAVE_MESSAGE).
					WithSourceIp(sm.Full(interfaceAddr)).
					WithGroupIp(sm.Full(groupAddr)).
					WithInterfaceName(sm.Full(interfaceName)),
			),
		}
	}).
	RegisterAtInit()
