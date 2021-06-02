package observer

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

func (k *ObserverKprobe) createBTFKprobe() {
	k.btfObj = bpf.GetBTF(ObserverBTF)
}

func (k *ObserverKprobe) getBTFKprobe() uintptr {
	return k.btfObj
}

func (k *ObserverKprobe) ConfigureBTF(ctx context.Context) error {
	// Find BTF metdaata and populate btf opaqu object
	if err := k.observerFindBTF(ctx); err != nil {
		return fmt.Errorf("hubble-fgs, Aborting kernel autodiscovery failed. %s\n", err)
	}
	k.createBTFKprobe()
	return nil
}

func btfFileExists(file string) error {
	_, err := os.Stat(file)
	return err
}

func (k *ObserverKprobe) observerFindBTF(ctx context.Context) error {
	if ObserverBTF == "" {
		var uname unix.Utsname

		// Alternative to auto-discovery and/or command line argument we
		// can also set via environment variable.
		fgsBtfEnv := os.Getenv("FGS_BTF")
		if fgsBtfEnv != "" {
			if _, err := os.Stat(fgsBtfEnv); err != nil {
				return err
			}
			ObserverBTF = fgsBtfEnv
			return nil
		}

		err := unix.Uname(&uname)
		if err != nil {
			return fmt.Errorf("Kernel version lookup (uname -r) failing. Use '--kernel' to set manually: %s\n", err)
		}
		n := bytes.IndexByte(uname.Release[:], 0)
		runFile := path.Join(HubbleLib, "metadata", "vmlinux-"+string(uname.Release[:n]))
		if _, err := os.Stat(runFile); err == nil {
			ObserverBTF = runFile
			return nil
		}
		logger.GetLogger().WithField("file", runFile).Info("candidate btf file does not exist")

		runFile = path.Join(HubbleLib, "btf")
		if _, err := os.Stat(runFile); err == nil {
			ObserverBTF = runFile
			return nil
		}
		logger.GetLogger().WithField("file", runFile).Info("candidate btf file does not exist")

		runFile = path.Join("/sys", "kernel", "btf", "vmlinux")
		if _, err := os.Stat(runFile); err == nil {
			ObserverBTF = runFile
			return nil
		}
		logger.GetLogger().WithField("file", runFile).Info("candidate btf file does not exist")

		return fmt.Errorf("Kernel version '%s' BTF search failed kernel is not included in supported list. Use --btf option to specify BTF path and/or '--kernel' to specify kernel version.", uname.Release[:n])
	} else {
		if err := btfFileExists(ObserverBTF); err != nil {
			return fmt.Errorf("User specified BTF does not exist. %s\n", err)
		}
	}
	return nil
}
