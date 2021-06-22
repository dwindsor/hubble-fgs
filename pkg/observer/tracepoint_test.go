//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//
package observer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// TestGenericTracepointSimple is a simple generic tracepoint test that creates a tracepoint for lseek()
func TestGenericTracepointSimple(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	lseekConf := GenericTracepointConf{
		Subsystem: "syscalls",
		Event:     "sys_enter_lseek",
		Args: []v1alpha1.KProbeArg{
			{Index: 7}, /* whence */
			{Index: 5}, /* fd */
		},
	}

	// initialize observer
	observer, err := getDefaultObserverWithWatchers(t)
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
	}

	// We do not call observer.Start(), so we need to start the sensor controller
	observer.ObserverSync, err = StartSensorCtl(observer.bpfDir, observer.mapDir, observer.ciliumDir)
	if err != nil {
		t.Fatalf("startSensorController failed: %s", err)
	}
	defer func() {
		err := observer.ObserverSync.stopSensorCtl(ctx)
		if err != nil {
			fmt.Printf("stopSensorController failed: %s\n", err)
		}
	}()

	// create and add sensor
	sensor, err := createGenericTracepointSensor([]GenericTracepointConf{lseekConf})
	if err != nil {
		t.Fatalf("failed to create generic tracepoint sensor: %s", err)
	}
	sensorName := "GtpLseekTest"
	if err := observer.ObserverSync.AddSensor(ctx, sensorName, sensor); err != nil {
		t.Fatalf("failed to add generic tracepoint sensor: %s", err)
	}
	defer func() {
		observer.ObserverSync.RemoveSensor(ctx, sensorName)
	}()
	if err := observer.ObserverSync.EnableSensor(ctx, sensorName); err != nil {
		t.Fatalf("EnableSensor error: %s", err)
	}
	defer func() {
		observer.ObserverSync.DisableSensor(ctx, sensorName)
	}()

	// sensor was enabled, test it
	arg0 := &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_SizeArg{SizeArg: 4444}}
	arg1 := &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_SizeArg{SizeArg: 18446744073709551615}} // -1
	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessTracepoint{
				ProcessTracepoint: &fgs.ProcessTracepoint{
					Subsys: "syscalls",
					Event:  "sys_enter_lseek",
					Args:   []*fgs.KprobeArgument{arg0, arg1},
				},
			},
		},
	}

	loopEvents(t, &exitWG, &execWG, observer, ctx)
	execWG.Wait()
	unix.Seek(-1, 0, 4444)
	exitWG.Wait()
	retries := jsonRetries
	time.Sleep(1000 * time.Millisecond)
	ok, err := JsonTestCompare(trace, exportFile, retries, 0)
	assert.NoError(t, err)
	assert.True(t, ok)
	testDone(t, observer)
}

func doTestGenericTracepointPidFilter(t *testing.T, conf GenericTracepointConf, selfOp func(), checkFn func(*fgs.ProcessTracepoint) error) {
	defer func() {
		if t.Failed() {
			if fname, err := jsonTestSaveCopy(nil); err != nil {
				t.Logf("Failed to save a copy of json out: %s", err)
			} else {
				t.Logf("Saved a copy of json out: %s", fname)
			}
		}
	}()

	if _, err := os.Stat("/sys/kernel/debug/tracing/events/syscalls"); os.IsNotExist(err) {
		t.Skip("cannot use syscall tracepoints (consider enabling CONFIG_FTRACE_SYSCALLS)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5000*time.Millisecond)
	defer cancel()

	pid := int(getMyPid())
	t.Logf("filtering for my pid (%d)", pid)
	pidSelector := v1alpha1.PIDSelector{
		Operator:       "In",
		IsNamespacePID: false,
		FollowForks:    true,
		Values:         []uint32{uint32(pid)},
	}

	if len(conf.Selectors) == 0 {
		conf.Selectors = make([]v1alpha1.KProbeSelector, 1)
	}
	conf.Selectors[0].MatchPIDs = append(conf.Selectors[0].MatchPIDs, pidSelector)
	observer, err := getDefaultObserverWithWatchers(t)
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
	}
	// We do not call observer.Start(), so we need to start the sensor controller
	observer.ObserverSync, err = StartSensorCtl(observer.bpfDir, observer.mapDir, observer.ciliumDir)
	if err != nil {
		t.Fatalf("startSensorController failed: %s", err)
	}
	defer func() {
		err := observer.ObserverSync.stopSensorCtl(ctx)
		if err != nil {
			fmt.Printf("stopSensorController failed: %s\n", err)
		}
	}()

	// create and add sensor
	sensor, err := createGenericTracepointSensor([]GenericTracepointConf{conf})
	if err != nil {
		t.Fatalf("failed to create generic tracepoint sensor: %s", err)
	}
	sensorName := "GtpLseekTest"
	if err := observer.ObserverSync.AddSensor(ctx, sensorName, sensor); err != nil {
		t.Fatalf("failed to add generic tracepoint sensor: %s", err)
	}
	defer func() {
		observer.ObserverSync.RemoveSensor(ctx, sensorName)
	}()
	if err := observer.ObserverSync.EnableSensor(ctx, sensorName); err != nil {
		t.Fatalf("EnableSensor error: %s", err)
	}
	defer func() {
		observer.ObserverSync.DisableSensor(ctx, sensorName)
	}()

	var exitWG, execWG sync.WaitGroup
	loopEvents(t, &exitWG, &execWG, observer, ctx)
	execWG.Wait()
	selfOp()
	exitWG.Wait()

	tpEventsNr := 0
	checkEventFn := func(event *fgs.GetEventsResponse, t *testing.T) error {
		switch tpEvent := event.Event.(type) {
		case *fgs.GetEventsResponse_ProcessTracepoint:
			if err := checkFn(tpEvent.ProcessTracepoint); err != nil {
				return err
			}
			eventPid := tpEvent.ProcessTracepoint.Process.Pid.Value
			if int(eventPid) != pid {
				return fmt.Errorf("Unexpected pid=%d (filter is for pid %d)", eventPid, pid)
			}
			tpEventsNr += 1
			return nil
		default:
			return fmt.Errorf("not a tracepoint event: %T", tpEvent)

		}
		return errors.New("internal error")
	}

	if err := jsonTestCheck(t, nil, eventCheckerFn(checkEventFn)); err != nil {
		t.Logf("error: %s", err)
		t.Fail()
	}

	// NB: in some cases we get more events. I think this
	// might be to -EINTR or similar. Will need to include the return value
	// to do proper testing.
	if tpEventsNr < 1 {
		t.Logf("Got %d events while expecting at least 1", tpEventsNr)
		t.Fail()
	}

	testDone(t, observer)
}

func TestGenericTracepointPidFilterLseek(t *testing.T) {
	tracepointConf := GenericTracepointConf{
		Subsystem: "syscalls",
		Event:     "sys_enter_lseek",
	}

	op := func() {
		fmt.Printf("Calling lseek...\n")
		unix.Seek(-1, 0, 4444)
	}

	check := func(event *fgs.ProcessTracepoint) error {
		return nil
	}

	doTestGenericTracepointPidFilter(t, tracepointConf, op, check)
}

func TestGenericTracepointArgFilterLseek(t *testing.T) {
	fd_u := uint64(100)
	fd := 100
	whence_u := uint64(4444)
	whenceStr := "4444"
	whence := 4444

	tracepointConf := GenericTracepointConf{
		Subsystem: "syscalls",
		Event:     "sys_enter_lseek",
		Args: []v1alpha1.KProbeArg{
			v1alpha1.KProbeArg{
				Index: 7, /* whence */
			},
			v1alpha1.KProbeArg{
				Index: 5, /* fd */
			},
		},
		Selectors: []v1alpha1.KProbeSelector{
			{
				MatchArgs: []v1alpha1.ArgSelector{
					{
						Index:    7,
						Operator: "Equal",
						Values:   []string{whenceStr},
					},
				},
			},
		},
	}

	op := func() {
		fmt.Printf("Calling lseek...\n")
		unix.Seek(fd, 0, whence)
		unix.Seek(fd, 0, whence+1)
	}

	check := func(event *fgs.ProcessTracepoint) error {
		if len(event.Args) != 2 {
			return fmt.Errorf("unexpected number of arguments: %d", len(event.Args))
		}
		arg0, ok := event.Args[0].GetArg().(*fgs.KprobeArgument_SizeArg)
		if !ok {
			return fmt.Errorf("unexpected first arg: %s", event.Args[0])
		}
		xwhence := arg0.SizeArg
		if xwhence != whence_u {
			return fmt.Errorf("unexpected arg val. got:%d expecting:%d", xwhence, whence)
		}
		arg1, ok := event.Args[1].GetArg().(*fgs.KprobeArgument_SizeArg)
		if !ok {
			return fmt.Errorf("unexpected first arg: %s", event.Args[1])
		}
		xfd := arg1.SizeArg
		if xfd != fd_u {
			return fmt.Errorf("unexpected arg val. got:%d expecting:%d", xfd, fd)
		}
		return nil
	}

	doTestGenericTracepointPidFilter(t, tracepointConf, op, check)
}

func TestGenericTracepointMeta(t *testing.T) {
	tracepointConf := GenericTracepointConf{
		Subsystem: "syscalls",
		Event:     "sys_enter_write",
		Args: []v1alpha1.KProbeArg{
			v1alpha1.KProbeArg{
				Index: 5, /* fd */
			},
			v1alpha1.KProbeArg{
				Index:        6,     /* char *buf */
				SizeArgIndex: 7 + 1, /* count */

			},
		},
		Selectors: []v1alpha1.KProbeSelector{{
			MatchArgs: []v1alpha1.ArgSelector{{
				Index:    5,
				Operator: "eq",
				Values:   []string{"1"},
			}},
		}},
	}

	op := func() {
		syscall.Write(1, []byte("hello world"))
	}

	found := false
	check := func(event *fgs.ProcessTracepoint) error {
		if event.Subsys != "syscalls" {
			return fmt.Errorf("Unexpected subsys: %s", event.Subsys)
		}
		if event.Event != "sys_enter_write" {
			return fmt.Errorf("Unexpected subsys: %s", event.Event)
		}
		if len(event.Args) != 2 {
			return fmt.Errorf("Expecting single argument, but got %d", len(event.Args))
		}
		arg1_, ok := event.Args[1].GetArg().(*fgs.KprobeArgument_BytesArg)
		if !ok {
			return fmt.Errorf("Unexpected arg: %v", event.Args[1].GetArg())
		}
		arg1 := string(arg1_.BytesArg)
		if arg1 == "hello world" {
			found = true
		}
		return nil
	}

	doTestGenericTracepointPidFilter(t, tracepointConf, op, check)
	if !found {
		t.Logf("expected string not found")
		t.Fail()
	}
}
