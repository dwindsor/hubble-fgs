// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package debug

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/agwctl"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
)

var (
	peerFailPeer       string
	peerFailMembership bool
	peerFailAdjacency  bool
)

func init() {
	DebugCmd.AddCommand(peerFailCmd)
	peerFailCmd.Flags().StringVar(&peerFailPeer, "peer", "", "Peer IP address")
	peerFailCmd.Flags().BoolVar(&peerFailMembership, "membership", false, "Inject membership failure (triggers ha-takeover/ha-switchover)")
	peerFailCmd.Flags().BoolVar(&peerFailAdjacency, "adjacency", false, "Inject adjacency failure (results in ha-degraded state)")
}

var peerFailCmd = &cobra.Command{
	Use:          "peer-fail",
	SilenceUsage: true,
	Short:        "Inject HA peer failure",
	Long:         `Inject a debug failure for a peer's membership or adjacency criteria. Use 'agwctl ha debug peer-ok' to restore normal operation.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		if peerFailPeer == "" {
			return errors.New("--peer is required")
		}
		if peerFailMembership && peerFailAdjacency {
			return errors.New("--membership and --adjacency are mutually exclusive")
		}
		if !peerFailMembership && !peerFailAdjacency {
			return errors.New("one of --membership or --adjacency is required")
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		data := ipc.MessageData{
			Flags: map[string]string{
				"peer":       peerFailPeer,
				"membership": fmt.Sprintf("%t", peerFailMembership),
				"adjacency":  fmt.Sprintf("%t", peerFailAdjacency),
			},
		}

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_HA_PEER_FAIL, data)
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, agwctl.JSON)
		return nil
	},
}
