package main

import (
	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	_ "github.com/isovalent/hubble-fgs/pkg/commands/agwctl/policies"
)

func main() {
	agwctl.Execute()
}
