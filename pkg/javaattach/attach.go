// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.

package javaattach

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const attachTimeout = 10 * time.Second

// LoadNativeAgent asks an already-running HotSpot VM to load a native JVMTI
// library through its Linux Attach listener. It does not launch a Java helper.
func LoadNativeAgent(pid int, libraryPath, options string) error {
	if pid <= 1 {
		return fmt.Errorf("invalid JVM pid %d", pid)
	}
	if !filepath.IsAbs(libraryPath) || strings.ContainsRune(libraryPath, '\x00') {
		return errors.New("native agent path must be absolute and contain no NUL")
	}
	if strings.ContainsRune(options, '\x00') {
		return errors.New("agent options contain NUL")
	}
	if len(libraryPath) > 1024 || len(options) > 1024 {
		return errors.New("Attach argument exceeds HotSpot's 1024-byte limit")
	}

	attachPID, err := pidInTargetNamespace(pid)
	if err != nil {
		return fmt.Errorf("resolve JVM pid namespace identity: %w", err)
	}
	socket := filepath.Join("/proc", strconv.Itoa(pid), "root", "tmp", ".java_pid"+strconv.Itoa(attachPID))
	conn, err := net.DialTimeout("unix", socket, 250*time.Millisecond)
	if err != nil {
		trigger, err := startListener(pid, attachPID)
		if err != nil {
			return fmt.Errorf("start JVM Attach listener: %w", err)
		}
		deadline := time.Now().Add(attachTimeout)
		for time.Now().Before(deadline) {
			conn, err = net.DialTimeout("unix", socket, 250*time.Millisecond)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil {
			_ = os.Remove(trigger)
			return fmt.Errorf("connect to JVM Attach socket %s: %w", socket, err)
		}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(attachTimeout))
	return sendLoadRequest(conn, libraryPath, options)
}

func sendLoadRequest(conn net.Conn, libraryPath, options string) error {
	// Linux HotSpot Attach protocol: version, command, then three arguments.
	for _, value := range []string{"1", "load", libraryPath, "true", options} {
		if _, err := io.WriteString(conn, value+"\x00"); err != nil {
			return fmt.Errorf("write Attach request: %w", err)
		}
	}
	if unix, ok := conn.(*net.UnixConn); ok {
		if err := unix.CloseWrite(); err != nil {
			return fmt.Errorf("finish Attach request: %w", err)
		}
	}

	response := bufio.NewReader(conn)
	statusLine, err := response.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read Attach response status: %w", err)
	}
	status, err := strconv.Atoi(strings.TrimSpace(statusLine))
	if err != nil {
		return fmt.Errorf("parse Attach response status %q: %w", statusLine, err)
	}
	message, _ := io.ReadAll(io.LimitReader(response, 4097))
	if status != 0 {
		return fmt.Errorf("JVM rejected native agent load (status %d): %s", status, strings.TrimSpace(string(message)))
	}
	if strings.Contains(strings.ToLower(string(message)), "return code: -1") {
		return fmt.Errorf("JVM native agent reported failure: %s", strings.TrimSpace(string(message)))
	}
	return nil
}

func pidInTargetNamespace(pid int) (int, error) {
	status, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, err
	}
	return parseNamespacePID(status, pid)
}

func parseNamespacePID(status []byte, hostPID int) (int, error) {
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "NSpid:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "NSpid:"))
		if len(fields) == 0 {
			return 0, errors.New("empty NSpid field")
		}
		attachPID, err := strconv.Atoi(fields[len(fields)-1])
		if err != nil || attachPID <= 0 {
			return 0, fmt.Errorf("invalid NSpid field %q", line)
		}
		return attachPID, nil
	}
	// Older Linux kernels may omit NSpid when the process is not namespaced.
	return hostPID, nil
}

func startListener(pid, attachPID int) (string, error) {
	proc := filepath.Join("/proc", strconv.Itoa(pid))
	info, err := os.Stat(proc)
	if err != nil {
		return "", fmt.Errorf("stat target process: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("cannot determine JVM owner")
	}
	// Create under the target mount namespace's /tmp. Resolving /proc/<pid>/cwd
	// can cross a mount-namespace boundary with host-side ownership semantics.
	trigger := filepath.Join(proc, "root", "tmp", ".attach_pid"+strconv.Itoa(attachPID))
	err = createAttachTrigger(trigger, int(stat.Uid), int(stat.Gid))
	if err != nil {
		return "", fmt.Errorf("create Attach trigger: %w", err)
	}
	if err := syscall.Kill(pid, syscall.SIGQUIT); err != nil {
		_ = os.Remove(trigger)
		return "", fmt.Errorf("signal JVM to start Attach listener: %w", err)
	}
	// HotSpot consumes and removes the trigger asynchronously after SIGQUIT.
	return trigger, nil
}
