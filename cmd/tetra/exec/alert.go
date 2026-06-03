// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package exec

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/cilium/tetragon/cmd/tetra/getevents"

	"github.com/cilium/tetragon/api/v1/tetragon"

	ossEncoder "github.com/cilium/tetragon/pkg/encoder"

	"github.com/isovalent/hubble-fgs/pkg/encoder"
)

var DefaultAlertsBucket = "alerts"

type alertStrings struct {
	cnt    string
	sev    string
	name   string
	msg    string
	alerts []*tetragon.Alert
}

func encodeEvents(a *alertStrings) *bytes.Buffer {
	var buf bytes.Buffer
	compactEncoder := encoder.NewEnterpriseEncoder(&buf, "always", true)

	if !verbose {
		return &buf
	}
	for _, e := range a.alerts {
		err := compactEncoder.EncodePrefix("\t   ", e.Event)
		if err != nil {
			continue
		}
	}
	return &buf
}

func prettyPrintAlert(alertMap map[string][]*tetragon.Alert, counts map[string]int) {
	colorer := ossEncoder.NewColorer(ossEncoder.ColorMode(ossEncoder.ColorMode(getevents.Options.Color)))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)

	// order printers
	crit := []alertStrings{}
	warn := []alertStrings{}
	info := []alertStrings{}
	unspec := []alertStrings{}

	for _, alerts := range alertMap {
		alert := alerts[0]
		a := alertStrings{}
		switch alert.Rule.Severity {
		case tetragon.AlertRuleMeta_UNSPECIFIED:
			a.sev = colorer.Cyan.Sprintf("%s", alert.Rule.Severity.String())
		case tetragon.AlertRuleMeta_INFO:
			a.sev = colorer.Cyan.Sprintf("%s", alert.Rule.Severity.String())
		case tetragon.AlertRuleMeta_WARNING:
			a.sev = colorer.Yellow.Sprintf("%s", alert.Rule.Severity.String())
		case tetragon.AlertRuleMeta_CRITICAL:
			a.sev = colorer.Red.Sprintf("%s", alert.Rule.Severity.String())
		}

		a.name = fmt.Sprint(alert.Rule.Name)
		a.msg = fmt.Sprint(alert.Rule.Message)
		a.cnt = fmt.Sprintf("%d", counts[alert.Rule.Name])
		a.alerts = alerts

		switch alert.Rule.Severity {
		case tetragon.AlertRuleMeta_UNSPECIFIED:
			unspec = append(unspec, a)
		case tetragon.AlertRuleMeta_INFO:
			info = append(info, a)
		case tetragon.AlertRuleMeta_WARNING:
			warn = append(warn, a)
		case tetragon.AlertRuleMeta_CRITICAL:
			crit = append(crit, a)
		}
	}

	for _, a := range crit {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", a.cnt, a.name, a.sev, a.msg)
		buf := encodeEvents(&a)
		fmt.Fprintf(w, "%s", buf.String())
	}
	for _, a := range warn {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", a.cnt, a.name, a.sev, a.msg)
		buf := encodeEvents(&a)
		fmt.Fprintf(w, "%s", buf.String())
	}
	for _, a := range info {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", a.cnt, a.name, a.sev, a.msg)
		buf := encodeEvents(&a)
		fmt.Fprintf(w, "%s", buf.String())
	}
	for _, a := range unspec {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", a.cnt, a.name, a.sev, a.msg)
		buf := encodeEvents(&a)
		fmt.Fprintf(w, "%s", buf.String())
	}
	w.Flush()
}

func getAlertModel(enableS3 bool, bucket string) (map[string][]*tetragon.Alert, map[string]int, error) {
	alertBin := make(map[string][]*tetragon.Alert)
	alertCount := make(map[string]int)
	fi, _ := os.Stdin.Stat()
	if fi.Mode()&os.ModeNamedPipe != 0 {
		decoder := json.NewDecoder(bufio.NewReader(os.Stdin))
		for {
			alert := &tetragon.Alert{}
			err := decoder.Decode(&alert)
			if err != nil && !errors.Is(err, io.EOF) {
				return alertBin, alertCount, err
			}
			if errors.Is(err, io.EOF) {
				break
			}
			alertBin[alert.Rule.Name] = append(alertBin[alert.Rule.Name], alert)
			alertCount[alert.Rule.Name]++
		}
	} else if enableS3 {
		return s3FetchAlerts(bucket)
	}
	return alertBin, alertCount, nil
}
