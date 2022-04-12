//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package observer

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
)

var (
	retryDelay = 2 * time.Second
)

func eventTypeString(ev interface{}) string {
	switch xev := ev.(type) {
	case *fgs.GetEventsResponse_ProcessConnect:
		return fmt.Sprintf("ProcessConnect(%s:%s->%s:%s)",
			xev.ProcessConnect.SourceIp, xev.ProcessConnect.SourcePort,
			xev.ProcessConnect.DestinationIp, xev.ProcessConnect.DestinationPort,
		)
	case *fgs.GetEventsResponse_ProcessListen:
		return fmt.Sprintf("ProcessListen(%s:%s)",
			xev.ProcessListen.Ip,
			xev.ProcessListen.Port)
	case *fgs.GetEventsResponse_ProcessAccept:
		return "ProcessAccept"
	case *fgs.GetEventsResponse_Tls:
		return "Tls"
	case *fgs.GetEventsResponse_ProcessDns:
		return "ProcessDns"
	case *fgs.GetEventsResponse_ProcessHttp:
		return "ProcessHttp"
	case *fgs.GetEventsResponse_ProcessSockstats:
		return "ProcessSockstats"
	case *fgs.GetEventsResponse_ProcessExec:
		return fmt.Sprintf("ProcessExec(proc.cmd=%s)", xev.ProcessExec.Process.Binary)
	case *fgs.GetEventsResponse_ProcessExit:
		return "ProcessExit"
	case *fgs.GetEventsResponse_ProcessClose:
		return "ProcessClose"
	case *fgs.GetEventsResponse_ProcessCred:
		return "ProcessCred"
	case *fgs.GetEventsResponse_InterfaceStats:
		return "InterfaceStats"
	case *fgs.GetEventsResponse_Test:
		return "Test"
	case *fgs.GetEventsResponse_ProcessKprobe:
		return fmt.Sprintf("Kprobe(proc.cmd=%s)", xev.ProcessKprobe.Process.Binary)
	case *fgs.GetEventsResponse_ProcessTracepoint:
		return fmt.Sprintf("Tracepoint(event=%s)", xev.ProcessTracepoint.Event)
	default:
		return fmt.Sprintf("<UNKNOWN:%T>", ev)
	}
}

func JsonCheck(jsonFile *os.File, checker ec.MultiResponseChecker, log ec.Logger) error {
	count := 0
	dec := json.NewDecoder(jsonFile)
	for dec.More() {
		var ev fgs.GetEventsResponse
		if err := dec.Decode(&ev); err != nil {
			return fmt.Errorf("unmarshal failed: %w", err)
		}
		count++
		prefix := fmt.Sprintf("jsonTestCheck/line:%04d ", count)
		done, err := checker.NextCheck(&ev, &ec.PrefixLogger{Prefix: prefix, Logger: log})
		prefix = fmt.Sprintf("%sevent:%s", prefix, eventTypeString(ev.Event))
		if done && err == nil {
			log.Logf("%s =>  FINAL MATCH ", prefix)
			log.Logf("jsonTestCheck: DONE!")
			return nil
		} else if err == nil {
			log.Logf("%s => MATCH, continuing", prefix)
		} else if done && err != nil {
			log.Logf("%s => terminating error: %s", prefix, err)
			return err
		} else {
			if _, ok := err.(ec.EventTypeError); !ok {
				log.Logf("%s => no match: %s, continuing", prefix, err)
			}
		}
	}

	if err := checker.FinalCheck(log); err != nil {
		return fmt.Errorf("jsonTestCheck: failed to match after %d events: %w", count, err)
	}
	return nil
}

func JsonTestCheck(t *testing.T, c ec.MultiResponseChecker) error {
	var err error

	jsonFname := testutils.GetExportFilename(t)

	// cleanup function: if test fails, mark export file to be kept
	defer func() {
		if err != nil {
			t.Log("test failed, marking export file to be kept")
			testutils.KeepExportFile(t)
		}
	}()

	// attempt to open the export file
	t.Logf("jsonTestCheck: openning: %s\n", jsonFname)
	jsonFile, err := os.Open(jsonFname)
	if err != nil {
		return fmt.Errorf("opening json file failed: %w.", err)
	}
	t.Cleanup(func() { jsonFile.Close() })

	cnt := 0
	for {
		err = JsonCheck(jsonFile, c, t)
		if err == nil {
			break
		}

		cnt++
		if cnt == jsonRetries {
			err = fmt.Errorf("JsonTestCheck failed after %d retries: %w", jsonRetries, err)
			break
		}
		t.Logf("JsonCheck (retry=%d) failed: %s. Retrying after %s", cnt, err, retryDelay)
		jsonFile.Seek(0, io.SeekStart)
		time.Sleep(retryDelay)
		c.Reset()
	}

	return err
}
