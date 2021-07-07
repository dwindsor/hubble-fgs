//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//
package btf

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"

	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/logger"

	"golang.org/x/sys/unix"
)

var (
	/* opaque pointer to C BTF object */
	btfObj = bpf.BTFNil

	btfFile string
)

func btfFileExists(file string) error {
	_, err := os.Stat(file)
	return err
}

func observerFindBTF(lib, btf string, ctx context.Context) (string, error) {
	if btf == "" {
		var uname unix.Utsname

		// Alternative to auto-discovery and/or command line argument we
		// can also set via environment variable.
		fgsBtfEnv := os.Getenv("FGS_BTF")
		if fgsBtfEnv != "" {
			if _, err := os.Stat(fgsBtfEnv); err != nil {
				return btf, err
			}
			return fgsBtfEnv, nil
		}

		err := unix.Uname(&uname)
		if err != nil {
			return btf, fmt.Errorf("Kernel version lookup (uname -r) failing. Use '--kernel' to set manually: %s\n", err)
		}
		n := bytes.IndexByte(uname.Release[:], 0)
		runFile := path.Join(lib, "metadata", "vmlinux-"+string(uname.Release[:n]))
		if _, err := os.Stat(runFile); err == nil {
			return runFile, nil
		}
		logger.GetLogger().WithField("file", runFile).Info("candidate btf file does not exist")

		runFile = path.Join(lib, "btf")
		if _, err := os.Stat(runFile); err == nil {
			return runFile, nil
		}
		logger.GetLogger().WithField("file", runFile).Info("candidate btf file does not exist")

		runFile = path.Join("/sys", "kernel", "btf", "vmlinux")
		if _, err := os.Stat(runFile); err == nil {
			return runFile, nil
		}
		logger.GetLogger().WithField("file", runFile).Info("candidate btf file does not exist")

		return btf, fmt.Errorf("Kernel version '%s' BTF search failed kernel is not included in supported list. Use --btf option to specify BTF path and/or '--kernel' to specify kernel version.", uname.Release[:n])
	} else {
		if err := btfFileExists(btf); err != nil {
			return btf, fmt.Errorf("User specified BTF does not exist. %s\n", err)
		}
	}
	return btf, nil
}

func NewBTF() (bpf.BTF, error) {
	return bpf.NewBTF(btfFile)
}

func InitCachedBTF(lib string, ctx context.Context) error {
	var err error

	// Find BTF metdaata and populate btf opaqu object
	btfFile, err = observerFindBTF(lib, "", ctx)
	if err != nil {
		return fmt.Errorf("hubble-fgs, Aborting kernel autodiscovery failed. %s\n", err)
	}
	btfObj, err = NewBTF()
	return err
}

func GetCachedBTF() bpf.BTF {
	return btfObj
}

func FreeCachedBTF() {
	if btfObj != bpf.BTFNil {
		btfObj.Close()
		btfObj = bpf.BTFNil
	}
}
