//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package file

var (
	FimPathBasedArchHooks = [...]FimHook{
		{"fexit", "__x64_sys_open", []FimFunc{{"int __x64_sys_open(const struct pt_regs*)", "fexit_sys_open.o", "__x64_sys_open", [][]MapInfo{{{"open_user_to_kernel_path", SharedMap}}, {{"file_errors_map", SharedMap}}, {{"file_openraw_result_map", SharedMap}}, {{"file_openraw_heap_map", PrivateMap}}, {{"file_config_map", SharedMap}}, {{"buffer_heap_map", PrivateMap}}, PathBasedSelectorMaps[:], BaseMaps[:]}}}},
		{"fexit", "__x64_sys_openat", []FimFunc{{"int __x64_sys_openat(const struct pt_regs*)", "fexit_sys_open.o", "__x64_sys_openat", [][]MapInfo{{{"open_user_to_kernel_path", SharedMap}}, {{"file_errors_map", SharedMap}}, {{"file_openraw_result_map", SharedMap}}, {{"file_openraw_heap_map", PrivateMap}}, {{"file_config_map", SharedMap}}, {{"buffer_heap_map", PrivateMap}}, PathBasedSelectorMaps[:], BaseMaps[:]}}}},
		{"fexit", "__x64_sys_openat2", []FimFunc{{"int __x64_sys_openat2(const struct pt_regs*)", "fexit_sys_open.o", "__x64_sys_openat2", [][]MapInfo{{{"open_user_to_kernel_path", SharedMap}}, {{"file_errors_map", SharedMap}}, {{"file_openraw_result_map", SharedMap}}, {{"file_openraw_heap_map", PrivateMap}}, {{"file_config_map", SharedMap}}, {{"buffer_heap_map", PrivateMap}}, PathBasedSelectorMaps[:], BaseMaps[:]}}}},
		{"fexit", "__x64_sys_creat", []FimFunc{{"int __x64_sys_creat(const struct pt_regs*)", "fexit_sys_open.o", "__x64_sys_creat", [][]MapInfo{{{"open_user_to_kernel_path", SharedMap}}, {{"file_errors_map", SharedMap}}, {{"file_openraw_result_map", SharedMap}}, {{"file_openraw_heap_map", PrivateMap}}, {{"file_config_map", SharedMap}}, {{"buffer_heap_map", PrivateMap}}, PathBasedSelectorMaps[:], BaseMaps[:]}}}},
	}
)
