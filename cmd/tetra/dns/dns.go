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
	"math"
	"strconv"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
)

func findAllocsIDs(ipMap dnsparser.IPToDomainMap) ([]uint32, error) {
	allocIDs := []uint32{}
	ids := uint32(0)
	for {
		exist, err := ipMap.InnerMapExist(ids)
		if err != nil {
			return nil, fmt.Errorf("failed finding if inner map exist: %w", err)
		}
		if !exist {
			break
		}
		allocIDs = append(allocIDs, ids)
		ids++
	}
	return allocIDs, nil
}

func NewDNSCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dns [mapID]",
		Short: "Debug the DNS BPF parser IP to domain map.",
		Long: `Debug the DNS BPF parser IP to domain map. You can give a mapID as argument to
print the appropriate map or let the command discover the available one for you.

Examples:
  # Print all available maps
  tetra debug dns

  # Print the map with ID 3
  tetra debug dns 3`,
		RunE: func(cmd *cobra.Command, args []string) error {
			allocIDs := []uint32{}
			if len(args) > 0 {
				largeMapID, err := strconv.Atoi(args[0])
				if err != nil {
					return fmt.Errorf("failed to parse map ID arg %q: %w", args[0], err)
				}
				if largeMapID > math.MaxUint32 {
					return fmt.Errorf("invalid map ID, %d is > to max uint32", largeMapID)
				}
				allocIDs = append(allocIDs, uint32(largeMapID))
			}

			ipMap, err := dnsparser.LoadNewIPToDomainMap()
			if err != nil {
				return fmt.Errorf("fail to load ip map: %w", err)
			}
			defer ipMap.Close()

			if len(allocIDs) == 0 {
				allocIDs, err = findAllocsIDs(ipMap)
				if err != nil {
					return fmt.Errorf("failed to discover the allocation IDs: %w", err)
				}
			}

			for _, mapID := range allocIDs {
				if len(allocIDs) > 1 {
					cmd.Printf("MapID:%d\n", mapID)
				}

				// Then print the actual array of IP and domain
				values, err := ipMap.Values(mapID)
				if err != nil {
					return fmt.Errorf("failed retrieving values: %w", err)
				}

				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
				fmt.Fprintln(w, "IP\tDOMAIN\t")
				for ip, domain := range values {
					fmt.Fprintf(w, "%s\t%s\n", ip, domain)
				}
				err = w.Flush()
				if err != nil {
					return fmt.Errorf("failed to flush writer: %w", err)
				}

				// Add a newline for multiple arrays if not reaching the end
				if len(allocIDs) > 1 && mapID != uint32(len(allocIDs)) {
					cmd.Println()
				}
			}

			return nil
		},
	}
}
