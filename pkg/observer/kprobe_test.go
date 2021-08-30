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
	"fmt"
	"io/ioutil"
	"strconv"
	"sync"
	"syscall"
	"testing"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestKprobeObjectLoad(t *testing.T) {
	writeReadHook := `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_write"
spec:
  description: "write hook"
  kprobes:
  - call: "__x64_sys_write"
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
      sizeargindex: 2
    - index: 2
      type: "size_t"
    selectors:
    - matchpids:
      - operator: In
        values:
        - 25587
    matchargs:
    - index: 0
      operator: Equal
      values:
      - "1"
`
	writeConfigHook := []byte(writeReadHook)
	err := ioutil.WriteFile(testConfigFile, writeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}
	kprobe, err := getDefaultObserver(t, withConfig(testConfigFile), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
	}
	initialSensor := createInitialObserverSensor()
	ObserverLoadSensor(kprobe.bpfDir, kprobe.mapDir, kprobe.ciliumDir, context.TODO(), initialSensor)
	kprobe.RemovePrograms()
}

// NB: This is similar to TestKprobeObjectWriteRead, but it's a bit easier to
// debug because we can write things on stdout which will not generate events.
func TestKprobeLseek(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	pidStr := strconv.Itoa(int(getMyPid()))
	fmt.Printf("pid=%s\n", pidStr)

	lseekConfigHook_ := `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_write"
spec:
  description: "lseek hook"
  kprobes:
  - call: "__x64_sys_lseek"
    return: false
    syscall: true
    args:
    - index: 0
      type: "int"
    selectors:
    - matchpids:
      - operator: In
        followforks: true
        isnamespacepid: false
        values:
        - ` + pidStr

	lseekConfigHook := []byte(lseekConfigHook_)
	err := ioutil.WriteFile(testConfigFile, lseekConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	kprobe, err := getDefaultObserverWithWatchers(t, withConfig(testConfigFile), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
	}
	LoopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWG.Wait()
	fmt.Printf("Calling lseek...\n")
	unix.Seek(-1, 0, 4444)
	exitWG.Wait()
	TestDone(t, kprobe)
}

func TestKprobeObjectWriteRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	pidStr := strconv.Itoa(int(getMyPid()))
	writeReadHook := `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_write"
spec:
  description: "write hook"
  kprobes:
  - call: "__x64_sys_write"
    return: false 
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
      sizeargindex: 3
    - index: 2
      type: "size_t"
    selectors:
    - matchpids:
      - operator: In
        followforks: true
        isnamespacepid: false
        values:
        - ` + pidStr + `
      matchargs:
      - index: 0
        operator: "Equal"
        values:
        - "1"
`
	writeConfigHook := []byte(writeReadHook)
	err := ioutil.WriteFile(testConfigFile, writeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	kpChecker := ec.NewKprobeChecker().
		WithFunctionName("__x64_sys_write").
		WithArgs([]ec.GenericArgChecker{
			ec.GenericArgIntCheck(1),
			ec.GenericArgBytesCheck([]byte("hello world")),
			ec.GenericArgSizeCheck(11),
		})
	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasKprobe(kpChecker).
			End(),
	)

	kprobe, err := getDefaultObserverWithWatchers(t, withConfig(testConfigFile), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	LoopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWG.Wait()
	_, err = syscall.Write(1, []byte("hello world"))
	exitWG.Wait()

	err = JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)
	TestDone(t, kprobe)
}

func TestKprobeObjectRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	// Create file with hello world to read
	fd, errno := syscall.Open("/tmp/testfile", syscall.O_CREAT|syscall.O_RDWR, 0x777)
	if fd < 0 {
		fmt.Printf("File open failed: %s\n", errno)
		t.Fatal()
	}
	fd2, errno := syscall.Open("/tmp/testfile", syscall.O_RDWR, 0x770)
	if fd2 < 0 {
		fmt.Printf("File open fro read failed: %s\n", errno)
		t.Fatal()
	}
	fdString := fmt.Sprint(fd2)
	pidStr := strconv.Itoa(int(getMyPid()))
	readHook := `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_read"
spec:
  description: "read hook"
  kprobes:
  - call: "__x64_sys_read"
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_buf"
      returncopy: true
    - index: 2
      type: "size_t"
    selectors:
    - matchpids:
      - operator: In
        followforks: true
        values:
        - ` + pidStr + `
      matchargs:
      - index: 0
        operator: "Equal"
        values:
        - ` + fdString

	readConfigHook := []byte(readHook)
	err := ioutil.WriteFile(testConfigFile, readConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	kpChecker := ec.NewKprobeChecker().
		WithFunctionName("__x64_sys_read").
		WithArgs([]ec.GenericArgChecker{
			ec.GenericArgIntCheck(int32(fd2)),
			ec.GenericArgBytesCheck([]byte("hello world")),
			ec.GenericArgSizeCheck(11),
		})
	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasKprobe(kpChecker).
			End(),
	)

	kprobe, err := getDefaultObserverWithWatchers(t, withConfig(testConfigFile), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	LoopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWG.Wait()
	hello := []byte("hello world")
	n, errno := syscall.Write(fd, hello)
	if n < 0 {
		fmt.Printf("syscall.Write failed: %s\n", errno)
		t.Fatal()
	}
	syscall.Fsync(fd)
	var readBytes = make([]byte, 11)
	i, errno := syscall.Read(fd2, readBytes)
	if i < 0 {
		fmt.Printf("syscall.Read failed: %s\n", errno)
		t.Fatal()
	}
	exitWG.Wait()

	err = JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)
	TestDone(t, kprobe)
}

// __x64_sys_openat trace
var (
	openArg0Check   = ec.GenericArgIntCheck(-100)
	openArg1Check   = ec.GenericArgStringCheck("/tmp/testfile")
	openArg2Check   = ec.GenericArgIsInt()
	openKprobeCheck = ec.NewKprobeChecker().
			WithFunctionName("__x64_sys_openat").
			WithArgs([]ec.GenericArgChecker{openArg0Check, openArg1Check, openArg2Check})

	openChecker = ec.NewOrderedMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasProcess(ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))).
			HasKprobe(openKprobeCheck).
			End(),
	)

	// this check fails if it find a kprobe event. It is used to test filters.
	noKprobeChecker = ec.NewAllMultiResponseChecker(
		ec.ResponseCheckerFn(
			func(r *fgs.GetEventsResponse, l ec.Logger) error {
				switch ev := r.Event.(type) {
				case *fgs.GetEventsResponse_ProcessKprobe:
					return fmt.Errorf("Unexpected event: %+v", ev)
				default:
					return nil
				}
			},
		),
	)
)

func testKprobeObjectFiltered(t *testing.T,
	readHook string,
	checker ec.MultiResponseChecker) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()

	// Create file to open later
	fd, errno := syscall.Open("/tmp/testfile", syscall.O_CREAT|syscall.O_RDWR, 0x777)
	if fd < 0 {
		fmt.Printf("File open failed: %s\n", errno)
		t.Fatal()
	}

	readConfigHook := []byte(readHook)
	err := ioutil.WriteFile(testConfigFile, readConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	kprobe, err := getDefaultObserverWithWatchers(t, withConfig(testConfigFile), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	LoopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWG.Wait()
	fd2, errno := syscall.Open("/tmp/testfile", syscall.O_RDWR, 0x770)
	if fd2 < 0 {
		fmt.Printf("File open from read failed: %s\n", errno)
		t.Fatal()
	}
	data := "hello world"
	n, err := syscall.Write(fd2, []byte(data))
	assert.Equal(t, len(data), n)
	assert.NoError(t, err)
	exitWG.Wait()
	err = JsonTestCheck(t, nil, checker)
	assert.NoError(t, err)
	TestDone(t, kprobe)
}

func TestKprobeObjectOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(getMyPid()))
	readHook := `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_read"
spec:
  description: "open filtered hook"
  kprobes:
  - call: "__x64_sys_openat"
    return: false
    syscall: true
    args:
    - index: 0
      type: int
    - index: 1
      type: "string"
    - index: 2
      type: "int"
    selectors:
    - matchpids:
      - operator: In
        followforks: true
        values:
        - ` + pidStr + `
      matchargs:
      - index: 1
        operator: "Equal"
        values:
        - "/tmp/testfile\0"
`
	testKprobeObjectFiltered(t, readHook, &openChecker)
}

func TestKprobeObjectMultiValueOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(getMyPid()))
	readHook := `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_read"
spec:
  description: "open filtered hook"
  kprobes:
  - call: "__x64_sys_openat"
    return: false
    syscall: true
    args:
    - index: 0
      type: int
    - index: 1
      type: "string"
    - index: 2
      type: "int"
    selectors:
    - matchpids:
      - operator: In
        followforks: true
        values:
        - ` + pidStr + `
      matchargs:
      - index: 1
        operator: "Equal"
        values:
        - "/tmp/foobar\0"
        - "/tmp/testfile\0"
`
	testKprobeObjectFiltered(t, readHook, &openChecker)
}

func TestKprobeObjectFilterOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(getMyPid()))
	readHook := `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_read"
spec:
  description: "open filtered hook"
  kprobes:
  - call: "__x64_sys_openat"
    return: false
    syscall: true
    args:
    - index: 0
      type: int
    - index: 1
      type: "string"
    - index: 2
      type: "int"
    selectors:
    - matchpids:
      - operator: In
        followforks: true
        values:
        - ` + pidStr + `
      matchargs:
      - index: 1
        operator: "Equal"
        values:
        - "/tmp/foofile\0"
`
	testKprobeObjectFiltered(t, readHook, &noKprobeChecker)
}

func TestKprobeObjectMultiValueFilterOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(getMyPid()))
	readHook := `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_read"
spec:
  description: "open filtered hook"
  kprobes:
  - call: "__x64_sys_openat"
    return: false
    syscall: true
    args:
    - index: 0
      type: int
    - index: 1
      type: "string"
    - index: 2
      type: "int"
    selectors:
    - matchpids:
      - operator: In
        followforks: true
        values:
        - ` + pidStr + `
      matchargs:
      - index: 1
        operator: "Equal"
        values:
        - "/tmp/foo\0"
        - "/tmp/bar\0"
`
	testKprobeObjectFiltered(t, readHook, &noKprobeChecker)
}

func TestKprobeObjectFilterPrefixOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(getMyPid()))
	readHook := `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_read"
spec:
  description: "open filtered hook"
  kprobes:
  - call: "__x64_sys_openat"
    return: false
    syscall: true
    args:
    - index: 0
      type: int
    - index: 1
      type: "string"
    - index: 2
      type: "int"
    selectors:
    - matchpids:
      - operator: In
        followforks: true
        values:
        - ` + pidStr + `
      matchargs:
      - index: 1
        operator: "Prefix"
        values:
        - "/tmp/testf"
`
	testKprobeObjectFiltered(t, readHook, &openChecker)
}

func TestKprobeObjectPostfixOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(getMyPid()))
	readHook := `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_read"
spec:
  description: "open filtered hook"
  kprobes:
  - call: "__x64_sys_openat"
    return: false
    syscall: true
    args:
    - index: 0
      type: int
    - index: 1
      type: "string"
    - index: 2
      type: "int"
    selectors:
    - matchpids:
      - operator: In
        followforks: true
        values:
        - ` + pidStr + `
      matchargs:
      - index: 1
        operator: "Postfix"
        values:
        - "testfile\0"
`
	testKprobeObjectFiltered(t, readHook, &openChecker)
}

func helloIovecWorldWritev() (err error) {
	var arrayOfBytes = make([][]byte, 3)

	h := []byte("hello")
	i := []byte(" iovec ")
	w := []byte("world")

	arrayOfBytes[0] = h
	arrayOfBytes[1] = i
	arrayOfBytes[2] = w
	_, err = unix.Writev(1, arrayOfBytes)
	return err
}

func TestKprobeObjectWriteVRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	var exitWG, execWG sync.WaitGroup
	defer cancel()
	pidStr := strconv.Itoa(int(getMyPid()))

	writeReadHook := `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "__x64_sys_writev"
spec:
  description: "write hook"
  kprobes:
  - call: "__x64_sys_writev"
    return: false
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "char_iovec"
      sizeargindex: 3
    selectors:
    - matchpids:
      - operator: In
        followforks: true
        values:
        - ` + pidStr + `
      matchargs:
      - index: 0
        operator: Equal
        values:
        - 1
`
	writeConfigHook := []byte(writeReadHook)
	err := ioutil.WriteFile(testConfigFile, writeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	kpChecker := ec.NewKprobeChecker().
		WithFunctionName("__x64_sys_writev").
		WithArgs([]ec.GenericArgChecker{
			ec.GenericArgIntCheck(1),
			ec.GenericArgBytesCheck([]byte("hello iovec world")),
		})

	checker := ec.NewOrderedMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasProcess(ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))).
			HasKprobe(kpChecker).
			End(),
	)

	kprobe, err := getDefaultObserverWithWatchers(t, withConfig(testConfigFile), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	LoopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWG.Wait()
	err = helloIovecWorldWritev()
	execWG.Wait()

	err = JsonTestCheck(t, nil, &checker)
	assert.NoError(t, err)
	TestDone(t, kprobe)
}

var (
	doOpenKprobeCheck = ec.NewKprobeChecker().
				WithFunctionName("do_filp_open").
				WithArgs([]ec.GenericArgChecker{openArg0Check, openArg1Check})

	doOpenChecker = ec.NewOrderedMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasKprobe(doOpenKprobeCheck).
			End(),
	)
)

func TestKprobeObjectFilenameOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(getMyPid()))
	readHook := `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_read"
spec:
  description: "open filtered hook"
  kprobes:
  - call: "do_filp_open"
    return: false
    syscall: false
    args:
    - index: 0
      type: int
    - index: 1
      type: "filename"
    selectors:
    - matchpids:
      - operator: In
        followforks: true
        values:
        - ` + pidStr + `
     `
	testKprobeObjectFiltered(t, readHook, &doOpenChecker)
}

func TestKprobeObjectReturnFilenameOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(getMyPid()))
	readHook := `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_read"
spec:
  description: "open filtered hook"
  kprobes:
  - call: "do_filp_open"
    return: true
    syscall: false
    args:
    - index: 0
      type: int
    - index: 1
      type: "filename"
    returnarg:
      type: file
    selectors:
    - matchpids:
      - operator: In
        followforks: true
        values:
        - ` + pidStr + `
     `
	testKprobeObjectFiltered(t, readHook, &doOpenChecker)
}

var (
	// NB: there seems to be a bug here, because the result we return is
	// tmp/testfile/. Until the bug is fixed, we just test the prefix.
	// see: https://github.com/isovalent/hubble-fgs/issues/693
	writeArg0 = ec.GenericArgFileChecker(ec.StringMatchAlways(), ec.PrefixStringMatch("tmp/testfile"))
	writeArg1 = ec.GenericArgBytesCheck([]byte("hello world"))
	writeArg2 = ec.GenericArgSizeCheck(11)

	writeFileKpChecker = ec.NewKprobeChecker().
				WithFunctionName("__x64_sys_write").
				WithArgs([]ec.GenericArgChecker{writeArg0, writeArg1, writeArg2})

	writeChecker = ec.NewOrderedMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasProcess(ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))).
			HasKprobe(writeFileKpChecker).
			End(),
	)
)

func TestKprobeObjectFileWrite(t *testing.T) {
	pidStr := strconv.Itoa(int(getMyPid()))
	readHook := `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_read"
spec:
  description: "open filtered hook"
  kprobes:
  - call: "fd_install"
    return: false
    syscall: false
    args:
    - index: 0
      type: int
    - index: 1
      type: "file"
    selectors:
    - matchpids:
      - operator: In
        followforks: true
        values:
        - ` + pidStr + `
      matchactions:
      - action: followfd
        argfd: 0
        argname: 1
  - call: "__x64_sys_write"
    syscall: true
    args:
    - index: 0
      type: "fd"
    - index: 1
      type: "char_buf"
      sizeargindex: 3
    - index: 2
      type: "size_t"
    selectors:
    - matchpids:
      - operator: In
        values:
        - ` + pidStr + `
`
	testKprobeObjectFiltered(t, readHook, &writeChecker)
}

func TestKprobeObjectFileWriteFiltered(t *testing.T) {
	pidStr := strconv.Itoa(int(getMyPid()))
	readHook := `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "sys_read"
spec:
  description: "open filtered hook"
  kprobes:
  - call: "fd_install"
    return: false
    syscall: false
    args:
    - index: 0
      type: int
    - index: 1
      type: "file"
    selectors:
    - matchpids:
      - operator: In
        followforks: true
        values:
        - ` + pidStr + `
      matchargs:
      - index: 1
        operator: "Equal"
        values:
        - "tmp/testfile"
      matchactions:
      - action: followfd
        argfd: 0
        argname: 1
  - call: "__x64_sys_write"
    syscall: true
    args:
    - index: 0
      type: "fd"
    - index: 1
      type: "char_buf"
      sizeargindex: 3
    - index: 2
      type: "size_t"
    selectors:
    - matchpids:
      - operator: In
        values:
        - ` + pidStr + `
      matchargs:
      - index: 0
        operator: "Equal"
        values:
        - "tmp/testfile"
`
	testKprobeObjectFiltered(t, readHook, &writeChecker)
}
