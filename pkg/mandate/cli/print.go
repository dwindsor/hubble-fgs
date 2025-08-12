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

	"github.com/fatih/color"

	api "github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/attempt"
)

type PrintConfig struct {
	AttemptsLog bool
	PrintAll    bool
}

func Print(o io.Writer, res *api.GetMandateStatusRes, cfg PrintConfig) {
	warnColor := color.New(color.FgYellow)
	noteColor := color.New(color.FgCyan)

	if conf := res.GetConf(); conf != nil {
		fmt.Fprintf(o, "url: %s (refresh every %v)\n", noteColor.Sprintf("%s", conf.GetUrl()), conf.GetRefreshPeriod().AsDuration())
	}

	fmt.Fprintf(o, "loaded mandate: ")
	if ldMandate := res.GetLoadedMandate(); ldMandate == nil {
		warnColor.Fprintf(o, "none\n")
	} else {
		fmt.Printf("%s:%q %s:%q %s:%q\n",
			noteColor.Sprintf("version"), ldMandate.Version,
			noteColor.Sprintf("loaded-at"), ldMandate.LoadedAt.AsTime(),
			noteColor.Sprintf("checksum"), ldMandate.Checksum)
	}

	log := res.GetLog()
	if log == nil {
		return
	}
	if cfg.AttemptsLog {
		attempt.Print(o, res.Log, attempt.PrintCfg{PrintAll: cfg.PrintAll})
	} else if len(log.Entries) > 0 {
		// by default, just print the latest entry if there was an error
		e0 := log.Entries[len(log.Entries)-1]
		res0 := e0.GetRes()
		if res0 != nil && !res0.Success {
			minLog := &api.AttemptLog{
				Total:    log.Total,
				Failures: log.Failures,
				Entries:  log.Entries[len(log.Entries)-1:],
			}
			attempt.Print(o, minLog, attempt.PrintCfg{PrintAll: false})
		}
	}
}
