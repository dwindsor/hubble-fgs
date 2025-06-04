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

import (
	"github.com/cilium/tetragon/pkg/option"
	"github.com/spf13/pflag"
)

func AddOSSpecificFlags(flags *pflag.FlagSet) {
	// some fixes to defaults related to https://github.com/cilium/tetragon/pull/2938
	flags.Lookup(option.KeyEnableProcessAncestors).Usage = "Include ancestors in process exec events"
	flags.Lookup(option.KeyEnableProcessAncestors).Value = newBoolValue(true, &option.Config.EnableProcessAncestors)
	flags.Lookup(option.KeyEnableProcessAncestors).DefValue = "true"
}
