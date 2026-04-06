// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package nxos

// Registration status constants.
const (
	// RegFailK8sAuth indicates registration failed due to invalid K8s token.
	RegFailK8sAuth = "invalid k8s service account token"
	// RegOk indicates registration succeeded.
	RegOk = ""
	// ConnOk indicates connection to controller succeeded.
	ConnOk = "connected ok with Hypershield controller"
	// ConnFailed indicates connection to controller failed.
	ConnFailed = "failed to connect with Hypershield controller"
)

// System state constants.
const (
	SysStFwDisable   = 0x0
	SysStDpuPending  = 0x1
	SysStConnPending = 0x2
	SysStFwReady     = 0x4
	SysStRedirDone   = 0x8
)

// Token file path.
const TokenFile = "/iox_data/k8sauth_token"
