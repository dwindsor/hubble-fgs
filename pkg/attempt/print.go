//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package attempt

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fatih/color"

	api "github.com/cilium/tetragon/api/v1/tetragon"
)

var (
	errColor  = color.New(color.FgRed)
	okColor   = color.New(color.FgGreen)
	noteColor = color.New(color.FgCyan)
)

type PrintCfg struct {
	PrintAll bool // do not try and detect repeats
}

func resultString(r *api.AttemptResult) (mark, errmsg string) {
	maxStrSize := 200

	if r.Success {
		mark = okColor.Sprintf("✅")
		errmsg = ""
	} else {
		mark = errColor.Sprintf("❌")
		errmsg = strings.TrimSpace(r.Error)
		if len(errmsg) > maxStrSize {
			errmsg = fmt.Sprintf("%s ...", errmsg[:maxStrSize])
		}
	}
	return
}

func infoString(errmsg string, res *api.Attempt) string {
	msg := ""
	if len(errmsg) > 0 {
		msg = fmt.Sprintf("%s=%q", errColor.Sprintf("err"), errmsg)
	}
	for _, info := range res.Info {
		if len(msg) > 0 {
			msg = msg + " "
		}
		msg = msg + fmt.Sprintf("%s=%q", noteColor.Sprintf("%s", info.GetKey()), info.GetVal())
	}
	return msg
}

func Print(o io.Writer, res *api.AttemptLog, cfg PrintCfg) {

	if res.Failures == 0 {
		fmt.Fprintf(o, "attempts log: (%s total attempts, no failures)\n",
			noteColor.Sprintf("%d", res.Total),
		)
	} else {
		fmt.Fprintf(o, "attempts log: (%s total attempts, %s failed)\n",
			noteColor.Sprintf("%d", res.Total),
			errColor.Sprintf("%d", res.Failures),
		)
	}

	var lastMark = ""
	var lastErrmsg = ""
	repeats := 0
	for i, e := range res.Entries {
		mark, errmsg := resultString(e.Res)
		if !cfg.PrintAll && i+1 != len(res.Entries) && mark == lastMark && errmsg == lastErrmsg {
			repeats++
			continue
		} else if repeats > 0 {
			fmt.Fprintf(o, "... repeated %d times ...\n", repeats)
			repeats = 0
		}
		lastMark = mark
		lastErrmsg = errmsg

		msg := infoString(errmsg, e)
		timeFn := func(x *api.Attempt) time.Duration {
			return time.Since(x.Time.AsTime()).Round(time.Second)
		}
		fmt.Fprintf(o, "[+%-5s] %s %-16s %s\n", timeFn(e), mark, e.Op, msg)

		if !e.Res.Success {
			for _, se := range e.Entries {
				smark, serrmsg := resultString(se.Res)
				smsg := infoString(serrmsg, se)
				fmt.Fprintf(o, "[+%-5s]     %s %-16s %s\n",
					time.Since(se.Time.AsTime()).Round(time.Second),
					smark, se.Op, smsg)
			}
		}
	}
	if repeats > 0 {
		fmt.Fprintf(o, "... repeated %d times\n", repeats)
	}
}
