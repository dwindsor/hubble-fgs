//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

//go:build !windows

package file

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	fm "github.com/isovalent/hubble-fgs/pkg/sensors/file/utils"
)

var (
	FimPathBasedArchHooks = [...]FimHook{
		{"fexit", "__arm64_sys_open", []FimFunc{{"int __arm64_sys_open(const struct pt_regs*)", "fexit_sys_open.o", "__arm64_sys_open", fm.NewSet([]tetragon.FileAction{tetragon.FileAction_FILE_OPENRAW}...)}}},
		{"fexit", "__arm64_sys_openat", []FimFunc{{"int __arm64_sys_openat(const struct pt_regs*)", "fexit_sys_open.o", "__arm64_sys_openat", fm.NewSet([]tetragon.FileAction{tetragon.FileAction_FILE_OPENRAW}...)}}},
		{"fexit", "__arm64_sys_openat2", []FimFunc{{"int __arm64_sys_openat2(const struct pt_regs*)", "fexit_sys_open.o", "__arm64_sys_openat2", fm.NewSet([]tetragon.FileAction{tetragon.FileAction_FILE_OPENRAW}...)}}},
		{"fexit", "__arm64_sys_creat", []FimFunc{{"int __arm64_sys_creat(const struct pt_regs*)", "fexit_sys_open.o", "__arm64_sys_creat", fm.NewSet([]tetragon.FileAction{tetragon.FileAction_FILE_OPENRAW}...)}}},
	}
)
