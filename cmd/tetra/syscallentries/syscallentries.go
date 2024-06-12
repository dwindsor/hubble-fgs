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
	"errors"
	"fmt"
	"log"

	"github.com/isovalent/hubble-fgs/pkg/syscallinfo"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "syscallentries",
		Short:   "list syscall entries",
		Long:    "",
		PreRunE: nil,
		RunE: func(_ *cobra.Command, args []string) error {
			var e *syscallinfo.MissingSyscalls
			entries, err := syscallinfo.SyscallNamesToEntries(args)

			if err != nil && !errors.As(err, &e) {
				log.Fatal(err)
			}
			for _, e := range entries {
				fmt.Println(e)
			}
			if err != nil {
				fmt.Printf("error: %s\n", err)
			}
			return nil

		},
	}
	return cmd
}
