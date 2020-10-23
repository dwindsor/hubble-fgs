// Copyright 2020 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package observer

// This bpf_lseek is a simple BPF program used for tests

var (
	ObserverLseekTest = bpfLoad{
		"", "bpf_lseek.o",
		"syscalls/sys_enter_lseek",
		"syscalls/sys_enter_lseek",
		"tracepoint/sys_enter_lseek",
		"test_lseek",

		false,
		true,
		"tracepoint",
		bpfLoadStateIdle(),

		-1,
	}
)

func init() {
	observerAllPrograms = append(observerAllPrograms, &ObserverLseekTest)
}
