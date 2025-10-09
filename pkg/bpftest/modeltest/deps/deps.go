// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package deps

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultDependencyTimeout is the default timeout for dependency checks
	DefaultDependencyTimeout = 30 * time.Second
	// DefaultPollInterval is the interval between dependency checks
	DefaultPollInterval = 100 * time.Millisecond
)

// ProcessRegistry tracks running processes by their RunID
type ProcessRegistry struct {
	mu        sync.RWMutex
	processes map[string]bool
}

// NewProcessRegistry creates a new process registry
func NewProcessRegistry() *ProcessRegistry {
	return &ProcessRegistry{
		processes: make(map[string]bool),
	}
}

// Register marks a process as started
func (pr *ProcessRegistry) Register(runID string) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	pr.processes[runID] = true
}

// IsRegistered checks if a process is registered
func (pr *ProcessRegistry) IsRegistered(runID string) bool {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	return pr.processes[runID]
}

// Dependency represents a condition that must be met before a binary can run
type Dependency interface {
	// Check returns true if the dependency condition is met
	Check(ctx context.Context, registry *ProcessRegistry) (bool, error)
	// String returns a human-readable description of the dependency
	String() string
}

// ProcessRunning checks if a process is running whose command line matches the provided regex
type ProcessRunning struct {
	Pattern *regexp.Regexp
}

// NewProcessRunning creates a new ProcessRunning dependency
func NewProcessRunning(pattern string) (*ProcessRunning, error) {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}
	return &ProcessRunning{Pattern: regex}, nil
}

func (pr *ProcessRunning) Check(_ context.Context, _ *ProcessRegistry) (bool, error) {
	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return false, fmt.Errorf("failed to read /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if directory name is a PID (numeric)
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}

		cmdlinePath := filepath.Join(procDir, entry.Name(), "cmdline")
		cmdlineBytes, err := os.ReadFile(cmdlinePath)
		if err != nil {
			// Process might have exited, continue to next
			continue
		}

		// /proc/pid/cmdline uses null bytes as separators
		cmdline := string(cmdlineBytes)
		cmdline = strings.ReplaceAll(cmdline, "\x00", " ")
		cmdline = strings.TrimSpace(cmdline)

		if cmdline == "" {
			continue
		}

		if pr.Pattern.MatchString(cmdline) {
			return true, nil
		}
	}

	return false, nil
}

func (pr *ProcessRunning) String() string {
	return fmt.Sprintf("ProcessRunning(%s)", pr.Pattern.String())
}

// ProcessStarted checks if a process with the given RunID has been started
type ProcessStarted struct {
	RunID string
}

// NewProcessStarted creates a new ProcessStarted dependency
func NewProcessStarted(runID string) *ProcessStarted {
	return &ProcessStarted{RunID: runID}
}

func (ps *ProcessStarted) Check(_ context.Context, registry *ProcessRegistry) (bool, error) {
	return registry.IsRegistered(ps.RunID), nil
}

func (ps *ProcessStarted) String() string {
	return fmt.Sprintf("ProcessStarted(%s)", ps.RunID)
}

// TCPPortOpen checks if a TCP port is open (being listened on)
type TCPPortOpen struct {
	Port uint16
}

// NewTCPPortOpen creates a new TCPPortOpen dependency
func NewTCPPortOpen(port uint16) *TCPPortOpen {
	return &TCPPortOpen{Port: port}
}

func (tpo *TCPPortOpen) Check(_ context.Context, _ *ProcessRegistry) (bool, error) {
	// Check both IPv4 and IPv6
	files := []string{"/proc/net/tcp", "/proc/net/tcp6"}

	for _, file := range files {
		if found, err := tpo.checkTCPFile(file); err != nil {
			return false, err
		} else if found {
			return true, nil
		}
	}

	return false, nil
}

func (tpo *TCPPortOpen) checkTCPFile(filename string) (bool, error) {
	file, err := os.Open(filename)
	if err != nil {
		// If file doesn't exist (e.g., no IPv6), that's okay
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to open %s: %w", filename, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Skip header line
	if !scanner.Scan() {
		return false, nil
	}

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Local address is in format "IP:PORT"
		localAddr := fields[1]
		parts := strings.Split(localAddr, ":")
		if len(parts) != 2 {
			continue
		}

		// Port is in hex
		portHex := parts[1]
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			continue
		}

		// State field - 0A means LISTEN
		state := fields[3]
		if state == "0A" && uint16(port) == tpo.Port {
			return true, nil
		}
	}

	return false, scanner.Err()
}

func (tpo *TCPPortOpen) String() string {
	return fmt.Sprintf("TCPPortOpen(%d)", tpo.Port)
}

// CheckDependencies checks all dependencies with the given timeout
func CheckDependencies(ctx context.Context, deps []Dependency, registry *ProcessRegistry, timeout time.Duration) error {
	if len(deps) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(DefaultPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("dependency check timed out after %v", timeout)
		case <-ticker.C:
			allSatisfied := true
			for _, dep := range deps {
				satisfied, err := dep.Check(ctx, registry)
				if err != nil {
					return fmt.Errorf("error checking dependency %s: %w", dep.String(), err)
				}
				if !satisfied {
					allSatisfied = false
					break
				}
			}
			if allSatisfied {
				return nil
			}
		}
	}
}
