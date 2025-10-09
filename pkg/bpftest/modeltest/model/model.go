// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package model

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/deps"
	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/image"
)

const defaultCmdTimeout = 1 * time.Minute

// Namespaces maps zero or more namespace names to a collection of Pods.
type Namespaces map[string]Pods

// Pods maps zero or more pod names to the corresponding Pod.
type Pods map[string]Pod

type Pod struct {
	// One or more containers that run as part of the Pod.
	// Must define at least one container.
	Containers Containers
}

type Containers map[string]Container

type Container struct {
	// The source for the container image.
	// Must define a source.
	ImageSource image.ImageSource
	// The process to run in the container.
	Cmd Binary
	// TODO: One or more kubectl execs to run.
	Execs []Binary
}

type Binaries []Binary

type Binary struct {
	Cmd              string
	Args             []string
	Timeout          time.Duration
	ConnectionChecks ConnectionChecks
	// Optional RunID for tracking this process in dependencies
	RunID string
	// Dependencies that must be satisfied before running this binary
	Dependencies []deps.Dependency
}

func (b Binary) String() string {
	return strings.Join(append([]string{b.Cmd}, b.Args...), " ")
}

func (b *Binary) Run(ctx context.Context, registry *deps.ProcessRegistry, statusChan chan CmdResult) {
	if b.Timeout == 0 {
		b.Timeout = defaultCmdTimeout
	}

	// Check dependencies first
	if len(b.Dependencies) > 0 {
		if err := deps.CheckDependencies(ctx, b.Dependencies, registry, deps.DefaultDependencyTimeout); err != nil {
			statusChan <- CmdResult{
				Err:  err,
				Cmd:  b.Cmd,
				Args: b.Args,
			}
			return
		}
	}

	ctx, cancel := context.WithTimeout(ctx, b.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, b.Cmd, b.Args...)

	// Register this process if it has a RunID
	if b.RunID != "" {
		registry.Register(b.RunID)
	}

	err := cmd.Run()
	statusChan <- CmdResult{
		Err:  err,
		Cmd:  b.Cmd,
		Args: b.Args,
	}
}

type CmdResult struct {
	Cmd  string
	Args []string
	Err  error
}

type ConnectionChecks []ConnectionCheck

type ConnectionCheck struct {
	TxBytes      UInt64Checker
	RxBytes      UInt64Checker
	TxDrops      UInt64Checker
	TxQuota      UInt64Checker
	TxQuotaUsage UInt64Checker
}

type UInt64Checker func(tb testing.TB, value uint64) bool

func StatsCheckerZero() func(tb testing.TB, value uint64) bool {
	return func(tb testing.TB, value uint64) bool {
		return assert.Zero(tb, value)
	}
}

func StatsCheckerNonZero() func(tb testing.TB, value uint64) bool {
	return func(tb testing.TB, value uint64) bool {
		return assert.NotZero(tb, value)
	}
}

func StatsCheckerBetween(lo, hi uint64) func(tb testing.TB, value uint64) bool {
	return func(tb testing.TB, value uint64) bool {
		return assert.GreaterOrEqualf(tb, value, lo, "%d should be in range (%d,%d]", value, lo, hi) &&
			assert.Lessf(tb, value, hi, "%d should be in range (%d,%d]", value, lo, hi)
	}
}

func StatsCheckerGreaterThan(lo uint64) func(tb testing.TB, value uint64) bool {
	return func(tb testing.TB, value uint64) bool {
		return assert.Greater(tb, value, lo)
	}
}

func StatsCheckerLessThan(hi uint64) func(tb testing.TB, value uint64) bool {
	return func(tb testing.TB, value uint64) bool {
		return assert.Less(tb, value, hi)
	}
}
