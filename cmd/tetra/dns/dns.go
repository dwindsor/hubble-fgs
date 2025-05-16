// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package dns

import (
	"fmt"
	"text/tabwriter"

	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	"github.com/spf13/cobra"
)

func NewDNSCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dns",
		Short: "Debug the DNS BPF parser IP to domain map.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ipMap, err := dnsparser.LoadNewIPToDomainMap()
			if err != nil {
				return fmt.Errorf("fail to load ip map: %w", err)
			}
			defer ipMap.Close()

			values, err := ipMap.Values()
			if err != nil {
				return fmt.Errorf("fail retrieving values: %w", err)
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "IP\tDOMAIN\t")
			for ip, domain := range values {
				fmt.Fprintf(w, "%s\t%s\n", ip, domain)
			}
			w.Flush()

			return nil
		},
	}
}
