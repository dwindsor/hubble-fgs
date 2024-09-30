// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package file

import (
	"fmt"
	"math"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	"github.com/isovalent/hubble-fgs/pkg/sensors/file"
	fm "github.com/isovalent/hubble-fgs/pkg/sensors/file/utils"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

func New() *cobra.Command {
	ret := &cobra.Command{
		Use:          "file-debug",
		Short:        "debug information for file sensor",
		Hidden:       true,
		SilenceUsage: true,
	}

	ret.AddCommand(
		printInodeMapCmd(),
		printLpmMapCmd(),
		supportEnforcementCmd(),
		supportDigestsCmd(),
	)

	return ret
}

func printInodeMapCmd() *cobra.Command {
	entryPath := ""
	inodeNum := uint64(0)
	devMajor := uint32(math.MaxUint32)
	devMinor := uint32(math.MaxUint32)
	action := uint32(math.MaxUint32)

	ret := &cobra.Command{
		Use:   "inode-map [path]",
		Short: "dump inode-map contents",
		Args:  cobra.ExactArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			filter := func(key *fileapi.InodeKey, val *fileapi.InodeVal) bool {
				if entryPath != "" && entryPath != string(val.FullPath[:val.PathSize]) {
					return false
				}
				if inodeNum != 0 && inodeNum != key.Ino {
					return false
				}
				if devMajor != uint32(math.MaxUint32) && devMajor != key.DevMajor {
					return false
				}
				if devMinor != uint32(math.MaxUint32) && devMinor != key.DevMinor {
					return false
				}
				if action != uint32(math.MaxUint32) && action != val.Action {
					return false
				}
				return true
			}
			path := args[0]
			err := fm.PrintInodeMap(path, filter)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Printing failed!")
			}
		},
	}

	flags := ret.Flags()
	flags.StringVar(&entryPath, "path", entryPath, "entry path")
	flags.Uint64Var(&inodeNum, "ino", inodeNum, "inode number")
	flags.Uint32Var(&devMajor, "major", devMajor, "major device id")
	flags.Uint32Var(&devMinor, "minor", devMajor, "minor device id")
	flags.Uint32Var(&action, "action", action, "action (0 ignore, 1 match)")
	viper.BindPFlags(flags)

	return ret
}

func printLpmMapCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lpm-map [path]",
		Short: "dump lpm-map contents",
		Args:  cobra.ExactArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			path := args[0]
			err := fm.PrintLPMMap(path)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Printing failed!")
			}
		},
	}
}

func supportEnforcementCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "support-enforcement",
		Short: "1 if host supports file enforcement, 0 otherwise",
		Args:  cobra.ExactArgs(0),
		Run: func(_ *cobra.Command, _ []string) {
			if utils.SupportEnforcement() {
				fmt.Print("1")
			} else {
				fmt.Print("0")
			}
		},
	}
}

func supportDigestsCmd() *cobra.Command {
	objDir := ""

	ret := &cobra.Command{
		Use:   "support-digests",
		Short: "the algorith name if digests are supported, NONE otherwise",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if objDir == "" {
				return fmt.Errorf("command line argument --objdir is required")
			}

			algo, err := file.ProbeImaEnabledAlgo(objDir, args[0], args[1:]...)
			if err != nil {
				fmt.Println("NONE")
				return err
			}
			fmt.Println(algo)
			return nil
		},
	}

	flags := ret.Flags()
	flags.StringVar(&objDir, "objdir", objDir, "directory that contains all the eBPF object files")
	viper.BindPFlags(flags)

	return ret
}
