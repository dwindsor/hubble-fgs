// go:build !linux
package alertrule

import "github.com/spf13/cobra"

// NB: For now, this only works in linux due to some dependencies.
func testCommand() *cobra.Command {
	return nil
}
