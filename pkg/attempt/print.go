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

	api "github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/fatih/color"
)

func Print(o io.Writer, res *api.AttemptLog) {
	errColor := color.New(color.FgRed)
	okColor := color.New(color.FgGreen)
	noteColor := color.New(color.FgCyan)

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

	var lastResult = ""
	repeats := 0
	for i, e := range res.Entries {
		var result string
		if e.Res.Success {
			mark := okColor.Sprintf("✅")
			result = fmt.Sprintf("%s", mark)
		} else {
			mark := errColor.Sprintf("❌")
			errStr := strings.TrimSpace(e.Res.Error)
			if len(errStr) > 120 {
				errStr = fmt.Sprintf("%s ...", errStr[:120])
			}
			result = fmt.Sprintf("%s: %s", mark, errStr)
		}

		if i+1 != len(res.Entries) && result == lastResult {
			repeats++
			continue
		} else if repeats > 0 {
			fmt.Fprintf(o, "   ... repeated %d times ...\n", repeats)
			repeats = 0
		}

		fmt.Fprintf(o, "[+%-5s] %s %s\n", time.Since(e.Time.AsTime()).Round(time.Second), e.Op, result)
		lastResult = result
	}
	if repeats > 0 {
		fmt.Fprintf(o, "   ... repeated %d times\n", repeats)
	}
}
