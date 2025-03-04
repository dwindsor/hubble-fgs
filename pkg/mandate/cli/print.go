//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

// CLI functionality for tetra

package cli

import (
	"fmt"
	"io"

	api "github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/fatih/color"
	"github.com/isovalent/hubble-fgs/pkg/attempt"
)

func Print(o io.Writer, res *api.GetMandateStatusRes) {
	warnColor := color.New(color.FgYellow)
	noteColor := color.New(color.FgCyan)

	if conf := res.GetConf(); conf != nil {
		fmt.Fprintf(o, "url: %s (refresh every %v)\n", noteColor.Sprintf("%s", conf.GetUrl()), conf.GetRefreshPeriod().AsDuration())
	}

	fmt.Fprintf(o, "loaded mandate: ")
	if ldMandate := res.GetLoadedMandate(); ldMandate == nil {
		warnColor.Fprintf(o, "none\n")
	}
	attempt.Print(o, res.Log)
}
