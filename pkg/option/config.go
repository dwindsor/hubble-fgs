//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package option

// Config contains all the configuration used by FGS.
var Config = config{
	// Initialize global defaults below.

	// ProcFS defaults to /proc.
	ProcFS: "/proc",

	// LogOpts contains logger parameters
	LogOpts: make(map[string]string),
}

type config struct {
	Debug              bool
	ProcFS             string
	KernelVersion      string
	HubbleLib          string
	BTF                string
	Verbosity          int
	IgnoreMissingProgs bool
	ForceSmallProgs    bool

	LogOpts map[string]string
}
