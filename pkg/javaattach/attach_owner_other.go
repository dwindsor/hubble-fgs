//go:build !linux

package javaattach

import "os"

func createAttachTrigger(path string, uid, gid int) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	if err := os.Chown(path, uid, gid); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
