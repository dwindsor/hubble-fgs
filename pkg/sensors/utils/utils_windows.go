//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package utils

func SkSkbParserRequired() bool {
	return false
}

func EnableV511Progs() bool {
	return false
}

func SupportProcessTree() bool {
	return false
}

// SupportCGroupSKBProbeRead checks if the kernel supports the probe_read helper on CGroup/SKB programs.
func SupportCGroupSKBProbeRead() bool {
	return false
}

// CGRoupSKBAvailable checks if the kernel supports CGroup/SKB programs, has support for large programs,
// and the CGroup/SKB programs have the perf_event_output helper.
func CGroupSKBAvailable() bool {
	return false
}

// UDPBindNeedsDummies checks if the kernel requires CGroup programs to be attached to the bind ops
// to trigger running the bind hooks. Returns true in case of errors.
func UDPBindNeedsDummies() bool {
	return true
}

// RawHooksAvailable checks if the two hooks we use for raw sockets are available.
func RawHooksAvailable() bool {
	return false
}
