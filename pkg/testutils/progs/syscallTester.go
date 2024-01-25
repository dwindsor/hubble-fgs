//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package progs

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/isovalent/hubble-fgs/pkg/testutils"
	"golang.org/x/sys/unix"
)

// This is what syscall-tester will execute.
func SyscallTesterMain() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		switch cmd := scanner.Text(); cmd {
		case "ping":
			fmt.Fprintf(os.Stdout, "pong\n")

		case "prctl":
			var cpu, node int
			_, _, err := unix.Syscall6(
				unix.SYS_PRCTL,
				uintptr(0xffff),
				0, 0, 0, 0, 0)
			fmt.Fprintf(os.Stdout, "%d\n", err)
			fmt.Fprintf(os.Stderr, "prctl: (err=%v) cpu=%d node=%d\n", err, cpu, node)

		case "getcpu":
			var cpu, node int
			_, _, err := unix.Syscall(
				unix.SYS_GETCPU,
				uintptr(unsafe.Pointer(&cpu)),
				uintptr(unsafe.Pointer(&node)),
				0)
			fmt.Fprintf(os.Stdout, "%d\n", err)
			fmt.Fprintf(os.Stderr, "getcpu: (err=%v) cpu=%d node=%d\n", err, cpu, node)

		case "exit":
			fmt.Fprintf(os.Stderr, "Exiting...\n")
			os.Exit(0)

		default:
			fmt.Fprintf(os.Stderr, "unknown cmd=%s\n", cmd)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing stdin: %v", err)
		os.Exit(1)
	}
}

// SyscallTester provies an interface to using syscall-tester, a simple program to test syscalls
type SyscallTester struct {
	Cmd          *exec.Cmd
	progStdout   io.ReadCloser
	progStdin    io.WriteCloser
	stdoutReader *bufio.Reader
}

//revive:disable:context-as-argument
func StartSyscallTester(t *testing.T, ctx context.Context) *SyscallTester {

	prog := testutils.RepoRootPath("contrib/tester-progs/syscall-tester")
	cmd := exec.CommandContext(ctx, prog)

	progStderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe filed: %v", err)
	}
	t.Cleanup(func() { progStderr.Close() })

	progStdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe filed: %v", err)
	}
	t.Cleanup(func() { progStdout.Close() })

	progStdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe filed: %v", err)
	}
	t.Cleanup(func() { progStdin.Close() })

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start syscall-tester: %v", err)
	}

	// print stderr in the logs
	go func() {
		scanner := bufio.NewScanner(progStderr)
		for scanner.Scan() {
			t.Logf("syscall-tester stderr> %s", scanner.Text())
		}
	}()

	return &SyscallTester{
		Cmd:          cmd,
		progStdout:   progStdout,
		progStdin:    progStdin,
		stdoutReader: bufio.NewReader(progStdout),
	}
}

func (st *SyscallTester) Process() *os.Process {
	return st.Cmd.Process
}

func (st *SyscallTester) Stop() error {
	s, err := st.Command("exit")
	if err == nil {
		return fmt.Errorf("unexpected output when terminating: '%s'", s)
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func (st *SyscallTester) Command(s string) (string, error) {
	_, err := fmt.Fprintf(st.progStdin, "%s\n", s)
	if err != nil {
		return "", err
	}
	s, err = st.stdoutReader.ReadString('\n')
	return strings.TrimSpace(s), err
}

func (st *SyscallTester) GetCPU() (int, error) {
	s, err := st.Command("getcpu")
	if err != nil {
		return 0, err
	}
	i, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return int(i), nil
}
