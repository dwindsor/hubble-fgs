// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package local

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"strconv"

	"github.com/cilium/tetragon/pkg/elf"
	"github.com/cilium/tetragon/pkg/kernels"
	ossOption "github.com/cilium/tetragon/pkg/option"
)

// kernelNotesPath exposes the running kernel's ELF notes, including its GNU
// build ID. Reading it does not require access to the vmlinux image.
const kernelNotesPath = "/sys/kernel/notes"

var (
	errNoBuildID       = errors.New("no GNU build-id note found")
	errNoKernelVersion = errors.New("kernel version unavailable")
)

func kernelBuildID() (string, error) {
	data, err := os.ReadFile(kernelNotesPath)
	if err != nil {
		return "", err
	}
	buildID, ok := elf.ParseBuildIdFromNotes(data, binary.NativeEndian)
	if !ok {
		return "", errNoBuildID
	}
	return hex.EncodeToString(buildID), nil
}

// kernelVersion returns the running kernel's major and minor version. It reports
// false when the version cannot be determined, in which case the labels are
// omitted. GetKernelVersion packs the version as major<<16 | minor<<8 | patch.
func kernelVersion() (major, minor int, ok bool) {
	version, _, err := kernels.GetKernelVersion(ossOption.Config.KernelVersion, ossOption.Config.ProcFS)
	if err != nil || version == 0 {
		return 0, 0, false
	}
	return version >> 16, (version >> 8) & 0xff, true
}

// kernelMajorVersion and kernelMinorVersion adapt kernelVersion to the label
// provider shape.
func kernelMajorVersion() (string, error) {
	major, _, ok := kernelVersion()
	if !ok {
		return "", errNoKernelVersion
	}
	return strconv.Itoa(major), nil
}

func kernelMinorVersion() (string, error) {
	_, minor, ok := kernelVersion()
	if !ok {
		return "", errNoKernelVersion
	}
	return strconv.Itoa(minor), nil
}
