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

package model

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	stdNet "net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/stretchr/testify/assert"

	"github.com/isovalent/ipa/application_model/v1alpha"
	k8sTypes "github.com/isovalent/ipa/common/k8s/type/v1alpha"
	commonNetV1 "github.com/isovalent/ipa/common/net/v1alpha"

	"github.com/isovalent/hubble-fgs/pkg/bpftest/modeltest/checklist"
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

	// The pod's restart policy. If not specified e.g. "", defaults to
	// corev1.RestartPolicyNever
	RestartPolicy corev1.RestartPolicy
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
	// If true, timeout/signal killed errors should not be treated as failures
	TimeoutExpected bool
	// If true, this binary is long lived. It should not be waited for, and
	// should be force killed when the test finishes.
	LongLived bool
	// If non-empty, pipe this string to the command's stdin
	Stdin string
	// If true, skip checking exec/exit counts
	SkipExecExitCounts bool
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

	var cmdCtx context.Context
	var cancel context.CancelFunc

	if b.LongLived {
		cmdCtx = ctx
	} else {
		cmdCtx, cancel = context.WithTimeout(ctx, b.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(cmdCtx, b.Cmd, b.Args...)

	// Set up stdin if provided
	if b.Stdin != "" {
		cmd.Stdin = bytes.NewBufferString(b.Stdin)
	}

	// Get the command name for prefixing
	cmdName := filepath.Base(b.Cmd)

	// Set up stdout and stderr pipes
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		statusChan <- CmdResult{
			Err:  fmt.Errorf("failed to create stdout pipe: %w", err),
			Cmd:  b.Cmd,
			Args: b.Args,
		}
		return
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		statusChan <- CmdResult{
			Err:  fmt.Errorf("failed to create stderr pipe: %w", err),
			Cmd:  b.Cmd,
			Args: b.Args,
		}
		return
	}

	// Register this process if it has a RunID
	if b.RunID != "" {
		registry.Register(b.RunID)
	}

	// Start the process
	err = cmd.Start()
	if err != nil {
		statusChan <- CmdResult{
			Err:  err,
			Cmd:  b.Cmd,
			Args: b.Args,
		}
		return
	}

	// Start goroutines to forward stdout and stderr
	go forwardOutput(stdout, cmdName, "stdout")
	go forwardOutput(stderr, cmdName, "stderr")

	if b.LongLived {
		registry.AddLongLivedCommand(cmd)
		err = nil
	} else {
		// Wait for the process to complete
		err = cmd.Wait()

		// If TimeoutExpected is true and the error is due to context timeout/signal kill, treat as success
		if b.TimeoutExpected && err != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				// Context timeout - this is expected
				err = nil
			} else if exitErr, ok := err.(*exec.ExitError); ok {
				// Check if process was killed by signal (typically SIGKILL from timeout)
				if exitErr.String() == "signal: killed" {
					err = nil
				}
			}
		}
	}

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

func (b *Binary) CheckConnections(tb testing.TB, connections []*v1alpha.ApplicationConnection) bool {
	connectionChecks := checklist.NewFromList("connection", b.ConnectionChecks)
	didFail := false
	for _, check := range b.ConnectionChecks {
		for _, connection := range connections {
			err := check.CheckConnection(connection)
			var skipErr ConnectionCheckSkip
			if err != nil && errors.As(err, &skipErr) {
				tb.Logf("skipping unmatched connection: %s", err.Error())
				continue
			}
			if !assert.NoError(tb, err, "connection check failed on %s", connection.String()) {
				didFail = true
			} else {
				connectionChecks.Check(check)
			}
		}
	}
	return !didFail && connectionChecks.AssertComplete(tb)
}

var _ error = ConnectionCheckSkip{}

type ConnectionCheckSkip struct {
	Err error
}

// Error implements error.
func (c ConnectionCheckSkip) Error() string {
	return fmt.Sprintf("skipped connection check due to: %s", c.Err)
}

var _ ConnectionChecker = (*DNSConnectionCheck)(nil)
var _ ConnectionChecker = (*IPConnectionCheck)(nil)
var _ ConnectionChecker = (*WorkloadConnectionCheck)(nil)

type ConnectionChecks []ConnectionChecker

type ConnectionChecker interface {
	CheckConnection(connection *v1alpha.ApplicationConnection) error
	String() string
}

type DNSConnectionCheck struct {
	Names            []string
	Port             UInt64Checker
	Protocol         commonNetV1.IPProtocol
	ObservationPoint v1alpha.ObservationPoint
	Stats            StatsCheck
}

// String implements ConnectionChecker.
func (check *DNSConnectionCheck) String() string {
	return fmt.Sprintf("DNSConnectionCheck{Names: %v}", check.Names)
}

// CheckConnection implements ConnectionChecker.
func (check *DNSConnectionCheck) CheckConnection(connection *v1alpha.ApplicationConnection) error {
	// Check destination type
	destination := connection.Destination.GetDns()
	if destination == nil {
		return ConnectionCheckSkip{Err: fmt.Errorf("destination type is not DNS")}
	}
	// Check port
	if check.Port != nil {
		if err := check.Port(connection.Destination.Port); err != nil {
			return ConnectionCheckSkip{Err: err}
		}
	}
	// Check names
	namesNeeded := checklist.NewFromList("destinationName", check.Names)
	for _, name := range destination.DestinationNames {
		namesNeeded.Check(name)
	}
	if !namesNeeded.IsComplete() {
		keys := make([]string, 0, len(namesNeeded.GetRemaining()))
		for k := range namesNeeded.GetRemaining() {
			keys = append(keys, k)
		}
		return ConnectionCheckSkip{Err: fmt.Errorf("missing destination name(s) %v", keys)}
	}
	// Check stats
	if err := check.Stats.CheckStats(connection.Stats); err != nil {
		return err
	}
	// Check protocol
	if check.Protocol != 0 && check.Protocol != connection.Protocol {
		return fmt.Errorf("protocol mismatch, expected %s, got %s", check.Protocol, connection.Protocol)
	}
	// Check observation point
	if check.ObservationPoint != 0 && check.ObservationPoint != connection.GetObservationPoint() {
		return fmt.Errorf("observation point mismatch, expected %s, got %s", check.ObservationPoint, connection.GetObservationPoint())
	}
	return nil
}

type IPConnectionCheck struct {
	CIDR     string
	Port     UInt64Checker
	Protocol commonNetV1.IPProtocol
	Stats    StatsCheck
}

// String implements ConnectionChecker.
func (check *IPConnectionCheck) String() string {
	return fmt.Sprintf("IPConnectionCheck{CIDR: %s}", check.CIDR)
}

// CheckConnection implements ConnectionChecker.
func (check *IPConnectionCheck) CheckConnection(connection *v1alpha.ApplicationConnection) error {
	// Check destination type
	destination := connection.Destination.GetIp()
	if destination == nil {
		return ConnectionCheckSkip{Err: fmt.Errorf("destination type is not IP")}
	}
	// Check port
	if check.Port != nil {
		if err := check.Port(connection.Destination.Port); err != nil {
			return ConnectionCheckSkip{Err: err}
		}
	}
	// Check IP
	destIP := stdNet.ParseIP(destination.Ip)
	cidr, err := parseCIDR(check.CIDR)
	if err != nil {
		panic(fmt.Sprintf("bad cidr %q: %s", check.CIDR, err))
	}
	if !cidr.Contains(destIP) {
		return ConnectionCheckSkip{Err: fmt.Errorf("IP %s does not match CIDR %s", destination.Ip, check.CIDR)}
	}
	// Check stats
	if err := check.Stats.CheckStats(connection.Stats); err != nil {
		return err
	}
	// Check protocol
	if check.Protocol != 0 && check.Protocol != connection.Protocol {
		return fmt.Errorf("protocol mismatch, expected %s, got %s", check.Protocol, connection.Protocol)
	}
	return nil
}

func parseCIDR(cidr string) (*stdNet.IPNet, error) {
	const V6_CIDR_MASK = "/128"
	const V4_CIDR_MASK = "/32"

	if stdNet.ParseIP(cidr) != nil {
		var mask string
		if stdNet.ParseIP(cidr).To4() != nil {
			mask = V4_CIDR_MASK
		} else {
			mask = V6_CIDR_MASK
		}
		_, result, err := stdNet.ParseCIDR(cidr + mask)
		if err != nil {
			return nil, err
		}
		return result, nil
	}
	// Otherwise just try to parse the cidr
	_, result, err := stdNet.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return result, nil
}

type WorkloadConnectionCheck struct {
	Name      string
	Namespace string
	Kind      k8sTypes.WorkloadKind
	Port      UInt64Checker
	Protocol  commonNetV1.IPProtocol
	Stats     StatsCheck
}

// String implements ConnectionChecker.
func (check *WorkloadConnectionCheck) String() string {
	return fmt.Sprintf("WorkloadConnectionCheck{Name: %s, Namespace: %s, Kind: %s}", check.Name, check.Namespace, check.Kind.String())
}

// CheckConnection implements ConnectionChecker.
func (check *WorkloadConnectionCheck) CheckConnection(connection *v1alpha.ApplicationConnection) error {
	// Check destination type
	destination := connection.Destination.GetWorkload()
	if destination == nil {
		return ConnectionCheckSkip{Err: fmt.Errorf("destination type is not Workload")}
	}
	// Check port
	if check.Port != nil {
		if err := check.Port(connection.Destination.Port); err != nil {
			return ConnectionCheckSkip{Err: err}
		}
	}
	// Check workload
	if check.Name != destination.Name {
		return ConnectionCheckSkip{Err: fmt.Errorf("name mismatch, expected %s, got %s", check.Name, destination.Name)}
	}
	if check.Namespace != destination.Namespace {
		return ConnectionCheckSkip{Err: fmt.Errorf("namespace mismatch, expected %s, got %s", check.Namespace, destination.Namespace)}
	}
	if check.Kind != destination.Kind {
		return ConnectionCheckSkip{Err: fmt.Errorf("workload kind mismatch, expected %s, got %s", check.Kind.String(), destination.Kind.String())}
	}
	// Check stats
	if err := check.Stats.CheckStats(connection.Stats); err != nil {
		return err
	}
	// Check protocol
	if check.Protocol != 0 && check.Protocol != connection.Protocol {
		return fmt.Errorf("protocol mismatch, expected %s, got %s", check.Protocol, connection.Protocol)
	}
	return nil
}

type StatsCheck struct {
	TxBytes               UInt64Checker
	RxBytes               UInt64Checker
	TxDropBytes           UInt64Checker
	TxDropPackets         UInt64Checker
	DefaultDropBytes      UInt64Checker
	DefaultDropPackets    UInt64Checker
	DefaultAllowBytes     UInt64Checker
	DefaultAllowPackets   UInt64Checker
	RxDropBytes           UInt64Checker
	RxDropPackets         UInt64Checker
	RxDefaultDropBytes    UInt64Checker
	RxDefaultDropPackets  UInt64Checker
	RxDefaultAllowBytes   UInt64Checker
	RxDefaultAllowPackets UInt64Checker
	Sessions              UInt64Checker
}

func (check *StatsCheck) CheckStats(stats *v1alpha.ConnectionStats) error {
	if check.TxBytes != nil {
		if err := check.TxBytes(stats.TxBytes); err != nil {
			return fmt.Errorf("txBytes check failed: %w", err)
		}
	}
	if check.RxBytes != nil {
		if err := check.RxBytes(stats.RxBytes); err != nil {
			return fmt.Errorf("rxBytes check failed: %w", err)
		}
	}
	if check.TxDropBytes != nil {
		if err := check.TxDropBytes(stats.TxDropBytes); err != nil {
			return fmt.Errorf("TxDropBytes check failed: %w", err)
		}
	}
	if check.TxDropPackets != nil {
		if err := check.TxDropPackets(stats.TxDropPackets); err != nil {
			return fmt.Errorf("TxDropPackets check failed: %w", err)
		}
	}
	if check.DefaultDropBytes != nil {
		if err := check.DefaultDropBytes(stats.DefaultDropBytes); err != nil {
			return fmt.Errorf("DefaultDropBytes check failed: %w", err)
		}
	}
	if check.DefaultDropPackets != nil {
		if err := check.DefaultDropPackets(stats.DefaultDropPackets); err != nil {
			return fmt.Errorf("DefaultDropPackets check failed: %w", err)
		}
	}
	if check.DefaultAllowBytes != nil {
		if err := check.DefaultAllowBytes(stats.DefaultAllowBytes); err != nil {
			return fmt.Errorf("DefaultAllowBytes check failed: %w", err)
		}
	}
	if check.DefaultAllowPackets != nil {
		if err := check.DefaultAllowPackets(stats.DefaultAllowPackets); err != nil {
			return fmt.Errorf("DefaultAllowPackets check failed: %w", err)
		}
	}
	if check.RxDropBytes != nil {
		if err := check.RxDropBytes(stats.RxDropBytes); err != nil {
			return fmt.Errorf("RxDropBytes check failed: %w", err)
		}
	}
	if check.RxDropPackets != nil {
		if err := check.RxDropPackets(stats.RxDropPackets); err != nil {
			return fmt.Errorf("RxDropPackets check failed: %w", err)
		}
	}
	if check.RxDefaultDropBytes != nil {
		if err := check.RxDefaultDropBytes(stats.RxDefaultDropBytes); err != nil {
			return fmt.Errorf("RxDefaultDropBytes check failed: %w", err)
		}
	}
	if check.RxDefaultDropPackets != nil {
		if err := check.RxDefaultDropPackets(stats.RxDefaultDropPackets); err != nil {
			return fmt.Errorf("RxDefaultDropPackets check failed: %w", err)
		}
	}
	if check.RxDefaultAllowBytes != nil {
		if err := check.RxDefaultAllowBytes(stats.RxDefaultAllowBytes); err != nil {
			return fmt.Errorf("RxDefaultAllowBytes check failed: %w", err)
		}
	}
	if check.RxDefaultAllowPackets != nil {
		if err := check.RxDefaultAllowPackets(stats.RxDefaultAllowPackets); err != nil {
			return fmt.Errorf("RxDefaultAllowPackets check failed: %w", err)
		}
	}
	if check.Sessions != nil {
		if err := check.Sessions(stats.Sessions); err != nil {
			return fmt.Errorf("sessions check failed: %w", err)
		}
	}
	return nil
}

type UInt64Checker func(value uint64) error

func UInt64Zero() UInt64Checker {
	return func(value uint64) error {
		if value != 0 {
			return fmt.Errorf("%d should be 0", value)
		}
		return nil
	}
}

func UInt64NonZero() UInt64Checker {
	return func(value uint64) error {
		if value == 0 {
			return fmt.Errorf("%d should not be 0", value)
		}
		return nil
	}
}

func UInt64Between(lo, hi uint64) UInt64Checker {
	return func(value uint64) error {
		if value < lo || value >= hi {
			return fmt.Errorf("%d should be in range (%d,%d]", value, lo, hi)
		}
		return nil
	}
}

func UInt64GreaterThan(lo uint64) UInt64Checker {
	return func(value uint64) error {
		if value <= lo {
			return fmt.Errorf("%d should be greater than %d", value, lo)
		}
		return nil
	}
}

func UInt64LessThan(hi uint64) UInt64Checker {
	return func(value uint64) error {
		if value >= hi {
			return fmt.Errorf("%d should be less than %d", value, hi)
		}
		return nil
	}
}

func UInt64Exactly(exact uint64) UInt64Checker {
	return func(value uint64) error {
		if value != exact {
			return fmt.Errorf("%d should be equal to %d", value, exact)
		}
		return nil
	}
}

// forwardOutput reads from the given reader and forwards to stderr with prefix
// Handles both line-by-line output and progress indicators with carriage returns
func forwardOutput(reader io.ReadCloser, cmdName, streamType string) {
	defer reader.Close()

	// Use a mutex to ensure atomic output per command
	var mu sync.Mutex

	// Buffer for handling carriage returns
	var currentLine strings.Builder

	// Read byte by byte to handle carriage returns properly
	buf := make([]byte, 1)
	for {
		n, err := reader.Read(buf)
		if n == 0 || err != nil {
			if err != nil && err != io.EOF {
				mu.Lock()
				fmt.Fprintf(os.Stderr, "%s> [error reading %s: %v]\n", cmdName, streamType, err)
				mu.Unlock()
			}
			break
		}

		char := buf[0]

		mu.Lock()
		switch char {
		case '\n':
			// End of line - print what we have
			if currentLine.Len() > 0 {
				fmt.Fprintf(os.Stderr, "%s> %s\n", cmdName, currentLine.String())
				currentLine.Reset()
			} else {
				fmt.Fprintf(os.Stderr, "%s>\n", cmdName)
			}
		case '\r':
			// Carriage return - print current line and reset (for progress indicators)
			if currentLine.Len() > 0 {
				fmt.Fprintf(os.Stderr, "%s> %s\n", cmdName, currentLine.String())
				currentLine.Reset()
			}
		default:
			// Regular character - add to current line
			currentLine.WriteByte(char)
		}
		mu.Unlock()
	}

	// Print any remaining content
	mu.Lock()
	if currentLine.Len() > 0 {
		fmt.Fprintf(os.Stderr, "%s> %s\n", cmdName, currentLine.String())
	}
	mu.Unlock()
}

type NotPresent struct {
	Host       Binaries
	Namespaces Namespaces
}
