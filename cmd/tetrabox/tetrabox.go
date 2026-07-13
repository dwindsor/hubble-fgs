// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package main

import (
	"fmt"
	"os"
	"path"

	fs_scanner "github.com/isovalent/hubble-fgs/cmd/tetragon-fs-scanner"
	"github.com/isovalent/hubble-fgs/pkg/tetra"
	"github.com/isovalent/hubble-fgs/pkg/tetragon"

	// Imported to allow sensors to be initialized inside init().
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"

	// Add enterprise-specific filters to the global registry
	_ "github.com/isovalent/hubble-fgs/pkg/filters"

	// sensor init
	_ "github.com/isovalent/hubble-fgs/pkg/sensorinit"
)

// tetrabox is a single binary for tetragon, tetra, and tetragon-fs-scanner
func main() {
	base := path.Base(os.Args[0])
	switch base {
	case "tetragon":
		if err := tetragon.Execute(); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	case "tetra":
		if err := tetra.New().Execute(); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	case "tetragon-fs-scanner":
		fs_scanner.Main()
		return
	case "tetrabox":
		fmt.Fprintln(os.Stderr, "tetrabox is a multi-call binary that combines three tetragon utilities: tetragon, tetra, and tetragon-fs-scanner")
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown binary name: %q\n", base)
		os.Exit(1)
	}
}
