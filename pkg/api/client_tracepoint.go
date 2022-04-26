//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package api

import "github.com/isovalent/hubble-fgs/pkg/api/processapi"

type MsgGenericTracepointArg interface{}

type MsgGenericTracepoint struct {
	Common       processapi.MsgCommon
	ProcessKey   processapi.MsgExecveKey
	Namespaces   processapi.MsgNamespaces
	Capabilities processapi.MsgCapabilities
	Id           int64
	ThreadId     uint64
	ActionId     uint64
}

type MsgGenericTracepointUnix struct {
	Common     processapi.MsgCommon
	ProcessKey processapi.MsgExecveKey
	Id         int64
	Subsys     string
	Event      string
	Args       []MsgGenericTracepointArg
}
