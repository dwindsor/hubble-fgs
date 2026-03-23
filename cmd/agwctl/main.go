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
	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/agwctl/config"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/agwctl/config/add"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/agwctl/config/remove"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/agwctl/device"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/agwctl/dpu"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/agwctl/ha"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/agwctl/ha/peers"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/agwctl/logging"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/agwctl/metrics"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/agwctl/mock"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/agwctl/mock/gnmi"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/agwctl/mock/vlan"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/agwctl/mock/vrf"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/agwctl/policies"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/agwctl/tech_support"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/agwctl/vlan"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/agwctl/vrf"
)

func main() {
	agwctl.Execute()
}
