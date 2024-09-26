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
	"fmt"
	"runtime"
	"slices"
	"strings"

	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/ftrace"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/tracing"
	"github.com/isovalent/hubble-fgs/pkg/abicalls"
)

var deprecatedSyscalls = (func() map[string]struct{} {
	ret := map[string]struct{}{
		// system calls that are older than what tetragon supports (4.19)
		"nfsservctl":      struct{}{}, // removed in 3.1
		"query_module":    struct{}{}, // removed in 2.6
		"create_module":   struct{}{}, // removed in 2.6
		"get_kernel_syms": struct{}{}, // removed in 2.6
	}

	// These syscalls are only suported on 32-bit kernels.
	// Tetragon does not support native i386 currently, but adding a check for clarity.
	if runtime.GOARCH != "386" {
		ret["vm86"] = struct{}{}
		ret["vm86old"] = struct{}{}
	}

	return ret
})()

// if we need to block (enforcement) retrieve a list of symbols we can inject errors in
// Otherwise, retrieve a call of available syscall entries
func availEntries(needBlock bool) (map[string]struct{}, error) {
	if needBlock {
		return errorInjectionEntries()
	}

	list, err := ftrace.ReadAvailFuncs("sys_")
	if err != nil {
		return nil, err
	}

	availMap := make(map[string]struct{}, len(list))
	for _, x := range list {
		availMap[x] = struct{}{}
	}
	return availMap, err
}

// getEIsFn returns the architecture-dependent function for retrieving ids and entries
func getEIsFn() (func(n string) ([]string, []uint32), error) {
	switch a := runtime.GOARCH; a {
	case "amd64":
		return func(n string) (entries []string, ids []uint32) {
			calls, ok := abicalls.CallsX86_64[n]
			if !ok {
				return
			}
			if c := calls.X64; c != nil {
				ids = append(ids, uint32(c.ID))
				entries = append(entries, c.Symbols...)
			}
			if c := calls.IA32; c != nil {
				ids = append(ids, uint32(c.ID)|tracing.Is32Bit)
				entries = append(entries, c.Symbols...)
			}
			return
		}, nil
	case "arm64":
		return func(n string) (entries []string, ids []uint32) {
			calls, ok := abicalls.CallsARM64[n]
			if !ok {
				return
			}
			if c := calls.ARM64; c != nil {
				ids = append(ids, uint32(c.ID))
				entries = append(entries, c.Symbols...)
			}
			if c := calls.ARM32; c != nil {
				ids = append(ids, uint32(c.ID)|tracing.Is32Bit)
				entries = append(entries, c.Symbols...)
			}
			return
		}, nil
	default:
		return nil, fmt.Errorf("unsupported arch: %s", a)
	}
}

func SyscallNamesToEntries(syscalls []string) ([]string, error) {
	l := make([]v1alpha1.SandboxSyscallItem, 0, len(syscalls))
	for _, s := range syscalls {
		l = append(l, v1alpha1.SandboxSyscallItem{Name: s})
	}

	ret, _, err := generateSyscalls(l, false)
	return ret, err
}

// generateSyscalls generates a list:
//   - syscall entries to hook into for enforcement
//   - syscall ids to check to filter
func generateSyscalls(l []v1alpha1.SandboxSyscallItem, needBlock bool) ([]string, []uint32, error) {

	// function to get entries and ids from the abicalls tables
	// For now we add both the 32- and 64- bit ABIs. Future work might extend the
	// SandboxSyscallItem to include ABI information.
	getEIs, err := getEIsFn()
	if err != nil {
		return nil, nil, err
	}

	entries := []string{}
	ids := []uint32{}
	missingSyscalls := []string{} // syscalls for which we do not have information in abicalls
	missingEntries := []string{}  // syscalls for which we were not able to find entries
	deprecated := []string{}      // syscalls that are deprecated and we ignore them
	availEntries, err := availEntries(needBlock)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get ftrace entries: %w", err)
	}

	for _, s := range l {
		name := strings.TrimPrefix(s.Name, "sys_")
		xes, xids := getEIs(name)
		if len(xids) == 0 {
			if _, ok := deprecatedSyscalls[name]; ok {
				deprecated = append(deprecated, s.Name)
			} else {
				missingSyscalls = append(missingSyscalls, s.Name)
			}
			continue
		}

		// add the default entry if it does not exist in the list
		if e, err := arch.AddSyscallPrefix(s.Name); err == nil {
			if !slices.Contains(xes, e) {
				xes = append(xes, e)
			}
		}
		// filter based on available entries
		xes = slices.DeleteFunc(xes, func(e string) bool {
			_, exists := availEntries[e]
			return !exists
		})
		if len(xes) == 0 {
			missingEntries = append(missingEntries, s.Name)
		}

		entries = append(entries, xes...)
		ids = append(ids, xids...)
	}

	if len(deprecated) > 0 {
		logger.GetLogger().
			WithField("syscalls", deprecated).
			Info("ignored deprecated (not supported by kernel) syscalls")
	}

	if len(missingSyscalls) > 0 || len(missingEntries) > 0 {
		logger.GetLogger().
			WithField("missing-ids", missingSyscalls).
			WithField("missing-entries", missingEntries).
			Warn("missing syscall information")
	}

	if len(ids) == 0 {
		return nil, nil, fmt.Errorf("no syscalls selected by policy, bailing out")
	}

	return entries, ids, nil
}
