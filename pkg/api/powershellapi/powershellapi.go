// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package powershellapi

import "github.com/cilium/tetragon/pkg/api/processapi"

type WindowsEvent struct {
	EventID int
	Tid     uint32
	Uid     uint32
}

type MsgPowerShellEvent struct {
	Common          processapi.MsgCommon    `align:"common"`
	ProcessKey      processapi.MsgExecveKey `align:"execve"`
	WinEvent        WindowsEvent
	ScriptBlockText string
	CommandLine     string
	ScriptPath      string
	PowerShellPath  string
	EngineVersion   string
	CommandName     string
	Payload         string
}

type MsgPowerShellCmdEvent struct {
	Common     processapi.MsgCommon    `align:"common"`
	ProcessKey processapi.MsgExecveKey `align:"execve"`
	WinEvent   WindowsEvent
}
