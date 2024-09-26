// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package syscallentries

import (
	"fmt"
	"log"

	"github.com/isovalent/hubble-fgs/pkg/sandboxpolicy"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "syscallentries",
		Short:   "list syscall entries",
		Long:    "",
		PreRunE: nil,
		RunE: func(_ *cobra.Command, args []string) error {
			entries, err := sandboxpolicy.SyscallNamesToEntries(args)
			if err != nil {
				log.Fatal(err)
			}
			for _, e := range entries {
				fmt.Println(e)
			}
			return nil

		},
	}
	return cmd
}
