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
	peerOkPeer       string
	peerOkMembership bool
	peerOkAdjacency  bool
)

func init() {
	DebugCmd.AddCommand(peerOkCmd)
	peerOkCmd.Flags().StringVar(&peerOkPeer, "peer", "", "Peer IP address")
	peerOkCmd.Flags().BoolVar(&peerOkMembership, "membership", false, "Clear membership debug failure")
	peerOkCmd.Flags().BoolVar(&peerOkAdjacency, "adjacency", false, "Clear adjacency debug failure")
}

var peerOkCmd = &cobra.Command{
	Use:          "peer-ok",
	SilenceUsage: true,
	Short:        "Clear HA peer debug failure",
	Long:         `Clear a debug failure for a peer's membership or adjacency criteria.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		if peerOkPeer == "" {
			return errors.New("--peer is required")
		}
		if peerOkMembership && peerOkAdjacency {
			return errors.New("--membership and --adjacency are mutually exclusive")
		}
		if !peerOkMembership && !peerOkAdjacency {
			return errors.New("one of --membership or --adjacency is required")
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		data := ipc.MessageData{
			Flags: map[string]string{
				"peer":       peerOkPeer,
				"membership": fmt.Sprintf("%t", peerOkMembership),
				"adjacency":  fmt.Sprintf("%t", peerOkAdjacency),
			},
		}

		ret, err := ipc.SendCmd(ctx, agwctl.CLI_SOCK, agwctl.CMD_HA_PEER_OK, data)
		if err != nil {
			return err
		}
		ipc.PrintResponse(ret, agwctl.JSON)
		return nil
	},
}
