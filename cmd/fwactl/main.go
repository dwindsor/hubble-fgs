// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package main

import (
	// _ "github.com/isovalent/hubble-fgs/pkg/commands/fwactl/dataplane/policies"

	"github.com/isovalent/hubble-fgs/pkg/commands/fwactl"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/fwactl/dataplane"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/fwactl/dataplane/clear"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/fwactl/dataplane/get"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/fwactl/dataplane/policer"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/fwactl/dataplane/syslog"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/fwactl/loadconfig"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/fwactl/logger"
)

func main() {
	fwactl.Execute()
}
