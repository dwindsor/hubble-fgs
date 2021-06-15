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
package observer

// This bpf_lseek is a simple BPF program used for tests

var (
	ObserverLseekTest = bpfLoad{
		"bpf_lseek.o",
		"syscalls/sys_enter_lseek",
		"syscalls/sys_enter_lseek",
		"tracepoint/sys_enter_lseek",
		"test_lseek",

		false,
		true,
		"tracepoint",
		bpfLoadStateIdle(),

		-1,

		struct{}{},
	}
)

func init() {
	observerAllPrograms = append(observerAllPrograms, &ObserverLseekTest)
}
