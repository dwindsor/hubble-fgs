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
