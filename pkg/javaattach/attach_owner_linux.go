//go:build linux

package javaattach

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
)

// createAttachTrigger creates the file with the target process's filesystem
// UID. Chowning /proc/<pid>/root/tmp from the host namespace can translate the
// numeric UID through a different mount/user-namespace mapping, which makes
// HotSpot reject the trigger even when the requested UID matches /proc status.
func createAttachTrigger(path string, uid, gid int) error {
	_ = gid // HotSpot checks the trigger owner UID; the group is not inspected.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	previous, _, errno := syscall.RawSyscall(syscall.SYS_SETFSUID, uintptr(uid), 0, 0)
	if errno != 0 {
		return fmt.Errorf("set filesystem uid for Attach trigger: %w", errno)
	}
	defer syscall.RawSyscall(syscall.SYS_SETFSUID, previous, 0, 0)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	created, err := os.Stat(path)
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	stat, ok := created.Sys().(*syscall.Stat_t)
	if !ok {
		_ = os.Remove(path)
		return fmt.Errorf("cannot inspect Attach trigger owner")
	}
	if int(stat.Uid) != uid {
		_ = os.Remove(path)
		return fmt.Errorf("Attach trigger owner mismatch: got %d, want %d", stat.Uid, uid)
	}
	return nil
}
