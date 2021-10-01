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
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"
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
	case *fgs.GetEventsResponse_ProcessExec:
		return fmt.Sprintf("ProcessExec(proc.cmd=%s)", xev.ProcessExec.Process.Binary)
	case *fgs.GetEventsResponse_ProcessExit:
		return "ProcessExit"
	case *fgs.GetEventsResponse_ProcessClose:
		return "ProcessClose"
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

// jsonTestSaveCopy saves a copy of the json file
func jsonTestSaveCopy(fnamePrefix string, jsonFile *os.File) (string, error) {
	var err error

	if fnamePrefix == "" {
		fnamePrefix = "hubble-fgs.gotest"
	}

	if jsonFile == nil {
		fmt.Printf("jsonTestIterate: openning: %s\n", exportFile)
		jsonFile, err = os.Open(exportFile)
		if err != nil {
			return "", fmt.Errorf("opening json file failed: %w", err)
		}
		defer jsonFile.Close()
	}

	out, err := ioutil.TempFile("/tmp/", fmt.Sprintf("%s.*.json", fnamePrefix))
	if err != nil {
		return "", fmt.Errorf("opening destination file failed: %w", err)
	}
	defer out.Close()

	_, err = io.Copy(out, jsonFile)
	if err != nil {
		return "", fmt.Errorf("failed to copy json file: %w", err)
	}

	os.Chmod(out.Name(), 0644)
	return out.Name(), nil
}

func JsonCheck(jsonFile *os.File, checker ec.MultiResponseChecker, log ec.Logger) error {
	count := 0
	dec := json.NewDecoder(jsonFile)
	for dec.More() {
		var ev fgs.GetEventsResponse
		if err := dec.Decode(&ev); err != nil {
			return fmt.Errorf("unmarshal failed: %w", err)
		}
		count += 1
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

func JsonTestCheck(t *testing.T, jsonFile *os.File, c ec.MultiResponseChecker) error {
	var err error
	if jsonFile == nil {
		fmt.Printf("jsonTestIterate: openning: %s\n", exportFile)
		jsonFile, err = os.Open(exportFile)
		if err != nil {
			return fmt.Errorf("opening json file failed: %w", err)
		}
	}
	defer func() {
		if err != nil {
			jsonFile.Seek(0, os.SEEK_SET)
			fnamePrefix := fmt.Sprintf("hubble-fgs.gotest.%s", t.Name())
			fname, _ := jsonTestSaveCopy(fnamePrefix, jsonFile)
			t.Logf("test failed: json file copied to %s", fname)
		}
		jsonFile.Close()
	}()

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
		jsonFile.Seek(0, os.SEEK_SET)
		time.Sleep(retryDelay)
		c.Reset()
	}

	return err
}
