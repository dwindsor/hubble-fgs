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
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	ecNew "github.com/isovalent/hubble-fgs/api/v1/fgs/codegen/eventchecker"
	"github.com/isovalent/hubble-fgs/api/v1/fgs/codegen/helpers"
	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	"github.com/sirupsen/logrus"
)

var (
	retryDelay = 2 * time.Second
)

// JsonEOF is a type of error where we went over all the events and there was no match.
//
// The reason to have a special error is that there are cases where the events
// we are looking for might not have been processed yet. In these cases, we
// need to retry.
type JsonEOF struct {
	// err is what FinalCheck() returned
	err error
	// count is the number of events we checked
	count int
}

// Error returns the error message
func (e *JsonEOF) Error() string {
	return fmt.Sprintf("JsonEOF: failed to match after %d events: err:%v", e.count, e.err)
}

// Unwrap returns the original error
func (e *JsonEOF) Unwrap() error {
	return e.err
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
		prefix = fmt.Sprintf("%sevent:%s", prefix, ec.EventTypeString(ev.Event))
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
		return &JsonEOF{
			count: count,
			err:   err,
		}
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
		return fmt.Errorf("opening json file failed: %w", err)
	}
	t.Cleanup(func() { jsonFile.Close() })

	cnt := 0
	for {
		err = JsonCheck(jsonFile, c, t)
		if err == nil {
			break
		}

		// if this is not a JsonEOF error, it means that the checker
		// concluded that there was a falure. Dont retry.
		var errEOF *JsonEOF
		if !errors.As(err, &errEOF) {
			break
		}

		cnt++
		if cnt > jsonRetries {
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

// JsonCheck checks a JSON string using the new eventchecker library.
func JsonCheckNew(jsonFile *os.File, checker ecNew.MultiEventChecker, log *logrus.Logger) error {
	count := 0
	dec := json.NewDecoder(jsonFile)
	for dec.More() {
		var ev fgs.GetEventsResponse
		if err := dec.Decode(&ev); err != nil {
			return fmt.Errorf("unmarshal failed: %w", err)
		}
		count++
		prefix := fmt.Sprintf("jsonTestCheck/line:%04d ", count)
		eType, err := helpers.EventTypeString(ev.Event)
		if err != nil {
			eType = "<UNKNOWN>"
		}
		matchPrefix := fmt.Sprintf("%sevent:%s", prefix, eType)
		done, err := ecNew.NextResponseCheck(checker, &ev, log)
		if done && err == nil {
			log.Infof("%s =>  FINAL MATCH ", matchPrefix)
			log.Infof("jsonTestCheck: DONE!")
			return nil
		} else if err == nil {
			log.Infof("%s => MATCH, continuing", matchPrefix)
		} else if done && err != nil {
			log.Errorf("%s => terminating error: %s", matchPrefix, err)
			return err
		} else {
			log.Infof("%s => no match: %s, continuing", matchPrefix, err)
		}
	}

	if err := checker.FinalCheck(log); err != nil {
		return &JsonEOF{
			count: count,
			err:   err,
		}
	}
	return nil
}

// JsonTestCheck checks a JSON file using the new eventchecker library.
func JsonTestCheckNew(t *testing.T, checker ecNew.MultiEventChecker) error {
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
	t.Logf("jsonTestCheck: opening: %s\n", jsonFname)
	jsonFile, err := os.Open(jsonFname)
	if err != nil {
		return fmt.Errorf("opening json file failed: %w", err)
	}
	t.Cleanup(func() { jsonFile.Close() })

	fieldLogger := logger.GetLogger()
	log, ok := fieldLogger.(*logrus.Logger)
	if !ok {
		return fmt.Errorf("failed to convert logger")
	}
	capturer := captureLog(t)
	log.SetOutput(capturer)
	defer capturer.Release()

	cnt := 0
	for {
		err = JsonCheckNew(jsonFile, checker, log)
		if err == nil {
			break
		}

		// if this is not a JsonEOF error, it means that the checker
		// concluded that there was a falure. Dont retry.
		var errEOF *JsonEOF
		if !errors.As(err, &errEOF) {
			break
		}

		cnt++
		if cnt > jsonRetries {
			err = fmt.Errorf("JsonTestCheck failed after %d retries: %w", jsonRetries, err)
			break
		}
		t.Logf("JsonCheck (retry=%d) failed: %s. Retrying after %s", cnt, err, retryDelay)
		jsonFile.Seek(0, io.SeekStart)
		time.Sleep(retryDelay)
	}

	return err
}

type logCapturer struct {
	*testing.T
	origOut io.Writer
}

func (tl logCapturer) Write(p []byte) (n int, err error) {
	tl.Logf((string)(p))
	return len(p), nil
}

func (tl logCapturer) Release() {
	logrus.SetOutput(tl.origOut)
}

// CaptureLog redirects logrus output to testing.Log
func captureLog(t *testing.T) *logCapturer {
	lc := logCapturer{T: t, origOut: logrus.StandardLogger().Out}
	if !testing.Verbose() {
		logrus.SetOutput(lc)
	}
	return &lc
}
