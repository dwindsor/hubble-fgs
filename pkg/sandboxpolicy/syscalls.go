//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package sandboxpolicy

import (
	"errors"
	"runtime"
	"strings"

	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/tracing"
	"github.com/cilium/tetragon/pkg/syscallinfo"
	eesyscallinfo "github.com/isovalent/hubble-fgs/pkg/syscallinfo"
)

// generateSyscalls generates a list:
//   - entries to enforce to
//   - syscall ids to check
func generateSyscalls(l []v1alpha1.SandboxSyscallItem) ([]string, []uint32, error) {

	var calls []string
	for _, s := range l {
		calls = append(calls, s.Name)
	}

	entries, err := eesyscallinfo.SyscallNamesToEntries(calls)
	if err != nil {
		var e *eesyscallinfo.MissingSyscalls
		if errors.As(err, &e) {
			logger.GetLogger().WithField("syscalls", strings.Join(e.Calls, ",")).Info("missing syscalls")
		} else {
			return nil, nil, err
		}
	}
	logger.GetLogger().WithField("entries", strings.Join(entries, ",")).Debug("monitored entries")

	ids := []uint32{}
	for _, call := range calls {
		var id int
		if runtime.GOARCH == "amd64" {
			x86ids := eesyscallinfo.GetX86IDs(call)
			if x86ids == nil {
				logger.GetLogger().WithField("syscall", call).Info("missing x86 syscall ids, skipping")
				continue
			}
			if x86ids.X64 != nil {
				ids = append(ids, uint32(*x86ids.X64))
			}
			if x86ids.X32 != nil {
				ids = append(ids, uint32(*x86ids.X64))
			}
			if x86ids.IA32 != nil {
				ids = append(ids, tracing.Is32Bit|uint32(*x86ids.X64))
			}
		} else {
			sc, is32 := arch.CutSyscallPrefix(call)
			sc = strings.TrimPrefix(sc, "sys_")
			if is32 {
				id = syscallinfo.GetSyscallID32(sc)
			} else {
				id = syscallinfo.GetSyscallID(sc)
			}

			if id == -1 {
				logger.GetLogger().WithField("syscall", call).Info("missing syscall id, skipping")
				continue
			}

			if is32 {
				id |= tracing.Is32Bit
			}
			ids = append(ids, uint32(id))
		}
	}

	return entries, ids, nil
}
