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
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"
	"github.com/isovalent/hubble-fgs/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"github.com/isovalent/hubble-fgs/pkg/sensors"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

var mountPath string = "/tmp2"

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
      sizeArgIndex: 2
    - index: 2
      type: "size_t"
    selectors:
    - matchPIDs:
      - operator: In
        values:
        - 25587
    matchArgs:
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
	obs, err := getDefaultObserver(t, withConfig(testConfigFile), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
	}
	initialSensor := sensors.GetInitialSensor()
	initialSensor.Load(context.TODO(), obs.bpfDir, obs.mapDir, obs.ciliumDir)
	obs.RemovePrograms()
}

// NB: This is similar to TestKprobeObjectWriteRead, but it's a bit easier to
// debug because we can write things on stdout which will not generate events.
func TestKprobeLseek(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	pidStr := strconv.Itoa(int(GetMyPid()))
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
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - ` + pidStr

	lseekConfigHook := []byte(lseekConfigHook_)
	err := ioutil.WriteFile(testConfigFile, lseekConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := getDefaultObserverWithWatchers(t, withConfig(testConfigFile), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
	}
	LoopEvents(t, &doneWG, &readyWG, obs, ctx)
	readyWG.Wait()
	fmt.Printf("Calling lseek...\n")
	unix.Seek(-1, 0, 4444)
	TestDone(t, obs)
}

func getTestKprobeObjectWRChecker() ec.MultiResponseChecker {
	rootNs := reader.GetCurrentNamespace()
	kpChecker := ec.NewKprobeChecker().
		WithFunctionName("__x64_sys_write").
		WithArgs([]ec.GenericArgChecker{
			ec.GenericArgIntCheck(1),
			ec.GenericArgBytesCheck([]byte("hello world")),
			ec.GenericArgSizeCheck(11),
		}).
		WithNs(rootNs)
	return ec.NewSingleMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasKprobe(kpChecker).
			End(),
	)
}

func runKprobeObjectWriteRead(t *testing.T, writeReadHook string) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	writeConfigHook := []byte(writeReadHook)
	err := ioutil.WriteFile(testConfigFile, writeConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	checker := getTestKprobeObjectWRChecker()

	obs, err := getDefaultObserverWithWatchers(t, withConfig(testConfigFile), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	LoopEvents(t, &doneWG, &readyWG, obs, ctx)
	readyWG.Wait()
	_, err = syscall.Write(1, []byte("hello world"))
	assert.NoError(t, err)

	err = JsonTestCheck(t, checker)
	assert.NoError(t, err)
	TestDone(t, obs)
}

func TestKprobeObjectWriteRead(t *testing.T) {
	myPid := GetMyPid()
	pidStr := strconv.Itoa(int(myPid))
	mntNsStr := strconv.FormatUint(uint64(reader.GetPidNsInode(myPid, "mnt")), 10)
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
      sizeArgIndex: 3
    - index: 2
      type: "size_t"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - ` + pidStr + `
      matchNamespaces:
      - namespace: Mnt
        operator: In
        values:
        - ` + mntNsStr + `
      matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "1"
`
	runKprobeObjectWriteRead(t, writeReadHook)
}

func TestKprobeObjectWriteReadNsOnly(t *testing.T) {
	myPid := GetMyPid()
	mntNsStr := strconv.FormatUint(uint64(reader.GetPidNsInode(myPid, "mnt")), 10)
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
      sizeArgIndex: 3
    - index: 2
      type: "size_t"
    selectors:
    - matchNamespaces:
      - namespace: Mnt
        operator: In
        values:
        - ` + mntNsStr + `
      matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "1"
`
	runKprobeObjectWriteRead(t, writeReadHook)
}

func TestKprobeObjectWriteReadPidOnly(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
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
      sizeArgIndex: 3
    - index: 2
      type: "size_t"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        isNamespacePID: false
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "1"
`
	runKprobeObjectWriteRead(t, writeReadHook)
}

func TestKprobeObjectRead(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	// Create file with hello world to read
	fd, errno := syscall.Open("/tmp/testfile", syscall.O_CREAT|syscall.O_RDWR, 0x777)
	if fd < 0 {
		t.Logf("File open failed: %s\n", errno)
		t.Fatal()
	}
	t.Cleanup(func() { syscall.Close(fd) })
	fd2, errno := syscall.Open("/tmp/testfile", syscall.O_RDWR, 0x770)
	if fd2 < 0 {
		t.Logf("File open fro read failed: %s\n", errno)
		t.Fatal()
	}
	t.Cleanup(func() { syscall.Close(fd2) })
	fdString := fmt.Sprint(fd2)
	pidStr := strconv.Itoa(int(GetMyPid()))
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
      returnCopy: true
    - index: 2
      type: "size_t"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
      matchArgs:
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

	obs, err := getDefaultObserverWithWatchers(t, withConfig(testConfigFile), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	LoopEvents(t, &doneWG, &readyWG, obs, ctx)
	readyWG.Wait()
	hello := []byte("hello world")
	n, errno := syscall.Write(fd, hello)
	if n < 0 {
		t.Logf("syscall.Write failed: %s\n", errno)
		t.Fatal()
	}
	syscall.Fsync(fd)
	var readBytes = make([]byte, 11)
	i, errno := syscall.Read(fd2, readBytes)
	if i < 0 {
		t.Logf("syscall.Read failed: %s\n", errno)
		t.Fatal()
	}

	err = JsonTestCheck(t, &checker)
	assert.NoError(t, err)
	TestDone(t, obs)
}

// __x64_sys_openat trace
var (
	openArg0Check    = ec.GenericArgIntCheck(-100)
	openArg1Check    = ec.GenericArgStringCheck("/tmp/testfile")
	openArg1CheckMnt = ec.GenericArgStringCheck(mountPath + "/testfile")
	openArg2Check    = ec.GenericArgIsInt()

	openKprobeCheck = ec.NewKprobeChecker().
			WithFunctionName("__x64_sys_openat").
			WithArgs([]ec.GenericArgChecker{openArg0Check, openArg1Check, openArg2Check})

	openKprobeCheckMnt = ec.NewKprobeChecker().
				WithFunctionName("__x64_sys_openat").
				WithArgs([]ec.GenericArgChecker{openArg0Check, openArg1CheckMnt, openArg2Check})

	openChecker = ec.NewOrderedMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasProcess(ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))).
			HasKprobe(openKprobeCheck).
			End(),
	)

	openCheckerMnt = ec.NewSingleMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasProcess(ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))).
			HasKprobe(openKprobeCheckMnt).
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
	checker ec.MultiResponseChecker,
	useMount bool) {

	mntPath := "/tmp"
	if useMount == true {
		mntPath = mountPath

		if err := os.Mkdir(mntPath, 0755); err != nil {
			t.Logf("Mkdir failed: %s\n", err)
			t.Skip()
		}
		if err := syscall.Mount("tmpfs", mntPath, "tmpfs", 0, ""); err != nil {
			t.Logf("Mount failed: %s\n", err)
			t.Skip()
		}
		t.Cleanup(func() {
			if err := syscall.Unmount(mntPath, 0); err != nil {
				t.Logf("Unmount failed: %s\n", err)
			}
			if err := os.Remove(mntPath); err != nil {
				t.Logf("Remove failed: %s\n", err)
			}
		})
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	filePath := mntPath + "/testfile"

	// Create file to open later
	fd, errno := syscall.Open(filePath, syscall.O_CREAT|syscall.O_RDWR, 0x777)
	if fd < 0 {
		t.Logf("File open failed: %s\n", errno)
		t.Fatal()
	}
	syscall.Close(fd)

	readConfigHook := []byte(readHook)
	err := ioutil.WriteFile(testConfigFile, readConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := getDefaultObserverWithWatchers(t, withConfig(testConfigFile), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	LoopEvents(t, &doneWG, &readyWG, obs, ctx)
	readyWG.Wait()
	fd2, errno := syscall.Open(filePath, syscall.O_RDWR, 0x770)
	if fd2 < 0 {
		t.Logf("File open from read failed: %s\n", errno)
		t.Fatal()
	}
	t.Cleanup(func() { syscall.Close(fd2) })
	data := "hello world"
	n, err := syscall.Write(fd2, []byte(data))
	assert.Equal(t, len(data), n)
	assert.NoError(t, err)
	err = JsonTestCheck(t, checker)
	assert.NoError(t, err)
	TestDone(t, obs)
}

func testKprobeObjectOpenHook(pidStr string, path string) string {
	return `
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
      - matchPIDs:
        - operator: In
          followForks: true
          values:
          - ` + pidStr + `
        matchArgs:
        - index: 1
          operator: "Equal"
          values:
          - "` + path + `/testfile\0"
  `
}

func TestKprobeObjectOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
	readHook := testKprobeObjectOpenHook(pidStr, "/tmp")
	testKprobeObjectFiltered(t, readHook, &openChecker, false)
}

func TestKprobeObjectOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
	readHook := testKprobeObjectOpenHook(pidStr, mountPath)
	testKprobeObjectFiltered(t, readHook, openCheckerMnt, true)
}

func testKprobeObjectMultiValueOpenHook(pidStr string, path string) string {
	return `
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
      - matchPIDs:
        - operator: In
          followForks: true
          values:
          - ` + pidStr + `
        matchArgs:
        - index: 1
          operator: "Equal"
          values:
          - "` + path + `/foobar\0"
          - "` + path + `/testfile\0"
  `
}

func TestKprobeObjectMultiValueOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
	readHook := testKprobeObjectMultiValueOpenHook(pidStr, "/tmp")
	testKprobeObjectFiltered(t, readHook, &openChecker, false)
}

func TestKprobeObjectMultiValueOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
	readHook := testKprobeObjectMultiValueOpenHook(pidStr, mountPath)
	testKprobeObjectFiltered(t, readHook, openCheckerMnt, true)
}

func TestKprobeObjectFilterOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
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
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "/tmp/foofile\0"
`
	testKprobeObjectFiltered(t, readHook, &noKprobeChecker, false)
}

func TestKprobeObjectMultiValueFilterOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
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
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "/tmp/foo\0"
        - "/tmp/bar\0"
`
	testKprobeObjectFiltered(t, readHook, &noKprobeChecker, false)
}

func testKprobeObjectFilterPrefixOpenHook(pidStr string, path string) string {
	return `
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
      - matchPIDs:
        - operator: In
          followForks: true
          values:
          - ` + pidStr + `
        matchArgs:
        - index: 1
          operator: "Prefix"
          values:
          - "` + path + `/testf"
  `
}

func TestKprobeObjectFilterPrefixOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
	readHook := testKprobeObjectFilterPrefixOpenHook(pidStr, "/tmp")
	testKprobeObjectFiltered(t, readHook, &openChecker, false)
}

func TestKprobeObjectFilterPrefixOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
	readHook := testKprobeObjectFilterPrefixOpenHook(pidStr, mountPath)
	testKprobeObjectFiltered(t, readHook, openCheckerMnt, true)
}

func testKprobeObjectFilterPrefixExactOpenHook(pidStr string, path string) string {
	return `
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
      - matchPIDs:
        - operator: In
          followForks: true
          values:
          - ` + pidStr + `
        matchArgs:
        - index: 1
          operator: "Prefix"
          values:
          - "` + path + `/testfile"
  `
}

func TestKprobeObjectFilterPrefixExactOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
	readHook := testKprobeObjectFilterPrefixExactOpenHook(pidStr, "/tmp")
	testKprobeObjectFiltered(t, readHook, &openChecker, false)
}

func TestKprobeObjectFilterPrefixExactOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
	readHook := testKprobeObjectFilterPrefixExactOpenHook(pidStr, mountPath)
	testKprobeObjectFiltered(t, readHook, openCheckerMnt, true)
}

func testKprobeObjectFilterPrefixSubdirOpenHook(pidStr string, path string) string {
	return `
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
      - matchPIDs:
        - operator: In
          followForks: true
          values:
          - ` + pidStr + `
        matchArgs:
        - index: 1
          operator: "Prefix"
          values:
          - "` + path + `/"
  `
}

func TestKprobeObjectFilterPrefixSubdirOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
	readHook := testKprobeObjectFilterPrefixSubdirOpenHook(pidStr, "/tmp")
	testKprobeObjectFiltered(t, readHook, &openChecker, false)
}

func TestKprobeObjectFilterPrefixSubdirOpenMount(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
	readHook := testKprobeObjectFilterPrefixSubdirOpenHook(pidStr, mountPath)
	testKprobeObjectFiltered(t, readHook, openCheckerMnt, true)
}

func TestKprobeObjectFilterPrefixMissOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
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
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 1
        operator: "Prefix"
        values:
        - "/foo/"
`
	testKprobeObjectFiltered(t, readHook, &noKprobeChecker, false)
}

func TestKprobeObjectPostfixOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
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
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
      matchArgs:
      - index: 1
        operator: "Postfix"
        values:
        - "testfile\0"
`
	testKprobeObjectFiltered(t, readHook, &openChecker, false)
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
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()
	pidStr := strconv.Itoa(int(GetMyPid()))

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
      sizeArgIndex: 3
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
      matchArgs:
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

	checker := ec.NewSingleMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasProcess(ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))).
			HasKprobe(kpChecker).
			End(),
	)

	obs, err := getDefaultObserverWithWatchers(t, withConfig(testConfigFile), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	LoopEvents(t, &doneWG, &readyWG, obs, ctx)
	readyWG.Wait()
	err = helloIovecWorldWritev()
	assert.NoError(t, err)

	err = JsonTestCheck(t, checker)
	assert.NoError(t, err)
	TestDone(t, obs)
}

var (
	doOpenKprobeCheck = ec.NewKprobeChecker().
				WithFunctionName("do_filp_open").
				WithArgs([]ec.GenericArgChecker{openArg0Check, openArg1Check})

	doOpenChecker = ec.NewSingleMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasKprobe(doOpenKprobeCheck).
			End(),
	)
)

func TestKprobeObjectFilenameOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
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
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
     `
	testKprobeObjectFiltered(t, readHook, doOpenChecker, false)
}

func TestKprobeObjectReturnFilenameOpen(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
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
    returnArg:
      type: file
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr + `
     `
	testKprobeObjectFiltered(t, readHook, doOpenChecker, false)
}

func testKprobeObjectFileWriteHook(pidStr string) string {
	return `
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
      - matchPIDs:
        - operator: In
          followForks: true
          values:
          - ` + pidStr + `
        matchActions:
        - action: followfd
          argFd: 0
          argName: 1
    - call: "__x64_sys_write"
      syscall: true
      args:
      - index: 0
        type: "fd"
      - index: 1
        type: "char_buf"
        sizeArgIndex: 3
      - index: 2
        type: "size_t"
      selectors:
      - matchPIDs:
        - operator: In
          values:
          - ` + pidStr + `
  `
}

func testKprobeObjectFileWriteFilteredHook(pidStr string, dir string) string {
	return `
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
      - matchPIDs:
        - operator: In
          followForks: true
          values:
          - ` + pidStr + `
        matchArgs:
        - index: 1
          operator: "Postfix"
          values:
          - "` + dir + `/testfile"
        matchActions:
        - action: followfd
          argFd: 0
          argName: 1
    - call: "__x64_sys_write"
      syscall: true
      args:
      - index: 0
        type: "fd"
      - index: 1
        type: "char_buf"
        sizeArgIndex: 3
      - index: 2
        type: "size_t"
      selectors:
      - matchPIDs:
        - operator: In
          values:
          - ` + pidStr + `
        matchArgs:
        - index: 0
          operator: "Postfix"
          values:
          - "` + dir + `/testfile"
  `
}

var (
	writeArg0    = ec.GenericArgFileChecker(ec.StringMatchAlways(), ec.SuffixStringMatch("/tmp/testfile"), ec.FullStringMatch(""))
	writeArg0Mnt = ec.GenericArgFileChecker(ec.StringMatchAlways(), ec.SuffixStringMatch(mountPath+"/testfile"), ec.FullStringMatch(""))
	writeArg1    = ec.GenericArgBytesCheck([]byte("hello world"))
	writeArg2    = ec.GenericArgSizeCheck(11)

	writeFileKpChecker = ec.NewKprobeChecker().
				WithFunctionName("__x64_sys_write").
				WithArgs([]ec.GenericArgChecker{writeArg0, writeArg1, writeArg2})

	writeChecker = ec.NewSingleMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasProcess(ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))).
			HasKprobe(writeFileKpChecker).
			End(),
	)

	writeFileKpCheckerMnt = ec.NewKprobeChecker().
				WithFunctionName("__x64_sys_write").
				WithArgs([]ec.GenericArgChecker{writeArg0Mnt, writeArg1, writeArg2})

	writeCheckerMnt = ec.NewSingleMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasProcess(ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))).
			HasKprobe(writeFileKpCheckerMnt).
			End(),
	)
)

func TestKprobeObjectFileWrite(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
	readHook := testKprobeObjectFileWriteHook(pidStr)
	testKprobeObjectFiltered(t, readHook, writeChecker, false)
}

func TestKprobeObjectFileWriteFiltered(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
	readHook := testKprobeObjectFileWriteFilteredHook(pidStr, "/tmp")
	testKprobeObjectFiltered(t, readHook, writeChecker, false)
}

func TestKprobeObjectFileWriteMount(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
	readHook := testKprobeObjectFileWriteHook(pidStr)
	testKprobeObjectFiltered(t, readHook, writeCheckerMnt, true)
}

func TestKprobeObjectFileWriteMountFiltered(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
	readHook := testKprobeObjectFileWriteFilteredHook(pidStr, mountPath)
	testKprobeObjectFiltered(t, readHook, writeCheckerMnt, true)
}

func createWriteChecker(path string, flags string) ec.MultiResponseChecker {
	writeArg0 = ec.GenericArgFileChecker(ec.StringMatchAlways(), ec.SuffixStringMatch(path), ec.FullStringMatch(flags))
	writeArg1 = ec.GenericArgBytesCheck([]byte("hello world"))
	writeArg2 = ec.GenericArgSizeCheck(11)

	writeFileKpChecker = ec.NewKprobeChecker().
		WithFunctionName("__x64_sys_write").
		WithArgs([]ec.GenericArgChecker{writeArg0, writeArg1, writeArg2})

	writeChecker = ec.NewSingleMultiResponseChecker(
		ec.NewKprobeEventChecker().
			HasProcess(ec.ProcessWithBinary(ec.SuffixStringMatch(selfBinary))).
			HasKprobe(writeFileKpChecker).
			End(),
	)

	return writeChecker
}

func corePathTest(t *testing.T, filePath string, readHook string, writeChecker ec.MultiResponseChecker) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), cmdWaitTime)
	defer cancel()

	// Create file to open later
	fd, errno := syscall.Open(filePath, syscall.O_CREAT|syscall.O_RDWR, 0x777)
	if fd < 0 {
		t.Logf("File open failed: %s\n", errno)
		t.Fatal()
	}
	syscall.Close(fd)

	readConfigHook := []byte(readHook)
	err := ioutil.WriteFile(testConfigFile, readConfigHook, 0644)
	if err != nil {
		t.Fatalf("writeFile(%s): err %s", testConfigFile, err)
	}

	obs, err := getDefaultObserverWithWatchers(t, withConfig(testConfigFile), withLib(fgsLib))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	LoopEvents(t, &doneWG, &readyWG, obs, ctx)
	readyWG.Wait()

	fd2, errno := syscall.Open(filePath, syscall.O_RDWR, 0x770)
	if fd2 < 0 {
		t.Logf("File open from read failed: %s\n", errno)
		t.Fatal()
	}
	t.Cleanup(func() { syscall.Close(fd2) })
	data := "hello world"
	n, err := syscall.Write(fd2, []byte(data))
	assert.Equal(t, len(data), n)
	assert.NoError(t, err)
	err = JsonTestCheck(t, writeChecker)
	assert.NoError(t, err)
	TestDone(t, obs)
}

func testMultipleMountsFiltered(t *testing.T, readHook string) {
	var pathStack []string

	// let's create /tmp2/tmp3/tmp4/tmp5 where each dir is a mount point
	path := "/"
	for i := 2; i < 6; i++ {
		path = filepath.Join(path, fmt.Sprintf("tmp%d", i))
		pathStack = append(pathStack, path)
		if err := os.Mkdir(path, 0755); err != nil {
			t.Logf("Mkdir failed: %s\n", err)
			t.Skip()
		}
		if err := syscall.Mount("tmpfs", path, "tmpfs", 0, ""); err != nil {
			t.Logf("Mount failed: %s\n", err)
			t.Skip()
		}
	}
	t.Cleanup(func() {
		// let's clear all
		for len(pathStack) > 0 {
			n := len(pathStack) - 1
			path := pathStack[n]
			if err := syscall.Unmount(path, 0); err != nil {
				t.Logf("Unmount failed: %s\n", err)
			}
			if err := os.Remove(path); err != nil {
				t.Logf("Remove failed: %s\n", err)
			}
			pathStack = pathStack[:n]
		}
	})

	filePath := path + "/testfile"

	writeChecker = createWriteChecker("/tmp4/tmp5/testfile", "unresolvedMountPoints")
	if kernels.EnableLargeProgs() {
		writeChecker = createWriteChecker("/tmp2/tmp3/tmp4/tmp5/testfile", "")
	}

	// the full path name is "/tmp2/tmp3/tmp4/tmp5/testfile"
	// but in the current implementation we support up to 2 mount points
	// so we will see "/tmp4/tmp5/testfile" and "unresolvedMountPoints" flag

	corePathTest(t, filePath, readHook, writeChecker)
}

func testMultiplePathComponentsFiltered(t *testing.T, readHook string) {
	var pathStack []string
	path := "/tmp"

	// let's create /tmp/0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16 where each dir is a directory
	for i := 0; i <= 16; i++ {
		path = filepath.Join(path, fmt.Sprintf("%d", i))
		pathStack = append(pathStack, path)
		if err := os.Mkdir(path, 0755); err != nil {
			t.Logf("Mkdir failed: %s\n", err)
			t.Skip()
		}
	}
	t.Cleanup(func() {
		if err := os.Remove(path + "/testfile"); err != nil {
			t.Logf("Remove testfile failed: %s\n", err)
		}
		// let's clear all
		for len(pathStack) > 0 {
			n := len(pathStack) - 1
			path := pathStack[n]
			if err := os.Remove(path); err != nil {
				t.Logf("Remove failed: %s\n", err)
			}
			pathStack = pathStack[:n]
		}
	})

	filePath := path + "/testfile"
	writeChecker = createWriteChecker("/6/7/8/9/10/11/12/13/14/15/16/testfile", "unresolvedPathComponents")
	if kernels.EnableLargeProgs() {
		writeChecker = createWriteChecker("/tmp/0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/testfile", "")
	}

	// the full path name is "/tmp/0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16"
	// but in the current implementation we support up to 13 path components
	// so we will see "/5/6/7/8/9/10/11/12/13/14/15/16/testfile"
	// and "unresolvedPathComponents" flag

	corePathTest(t, filePath, readHook, writeChecker)
}

func testMultipleMountPathFiltered(t *testing.T, readHook string) {
	var pathStack []string
	var dirStack []string
	path := "/"

	// let's create /tmp2/tmp3/tmp4/tmp5/0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16
	// tmp* are mount points
	// the rest are directories
	for i := 2; i < 6; i++ {
		path = filepath.Join(path, fmt.Sprintf("tmp%d", i))
		pathStack = append(pathStack, path)
		if err := os.Mkdir(path, 0755); err != nil {
			t.Logf("Mkdir failed: %s\n", err)
			t.Skip()
		}
		if err := syscall.Mount("tmpfs", path, "tmpfs", 0, ""); err != nil {
			t.Logf("Mount failed: %s\n", err)
			t.Skip()
		}
	}
	for i := 0; i <= 16; i++ {
		path = filepath.Join(path, fmt.Sprintf("%d", i))
		dirStack = append(dirStack, path)
		if err := os.Mkdir(path, 0755); err != nil {
			t.Logf("Mkdir failed: %s\n", err)
			t.Skip()
		}
	}
	t.Cleanup(func() {
		if err := os.Remove(path + "/testfile"); err != nil {
			t.Logf("Remove testfile failed: %s\n", err)
		}

		// let's clear all
		for len(dirStack) > 0 {
			n := len(dirStack) - 1
			path := dirStack[n]
			if err := os.Remove(path); err != nil {
				t.Logf("Remove failed: %s\n", err)
			}
			dirStack = dirStack[:n]
		}
		for len(pathStack) > 0 {
			n := len(pathStack) - 1
			path := pathStack[n]
			if err := syscall.Unmount(path, 0); err != nil {
				t.Logf("Unmount failed: %s\n", err)
			}
			if err := os.Remove(path); err != nil {
				t.Logf("Remove failed: %s\n", err)
			}
			pathStack = pathStack[:n]
		}
	})

	filePath := path + "/testfile"
	writeChecker = createWriteChecker("/[M]/tmp4/tmp5/[P]/6/7/8/9/10/11/12/13/14/15/16/testfile", "unresolvedMountPoints unresolvedPathComponents")
	if kernels.EnableLargeProgs() {
		writeChecker = createWriteChecker("/tmp2/tmp3/tmp4/tmp5/0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/testfile", "")
	}

	// the full path name is "/tmp2/tmp3/tmp4/tmp5/0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/testfile"
	// but in the current implementation we support up to 13 path components and 2 mount points
	// so we will see "/tmp4/tmp5/5/6/7/8/9/10/11/12/13/14/15/16/testfile"
	// and "unresolvedMountPoints unresolvedPathComponents"

	corePathTest(t, filePath, readHook, writeChecker)
}

func TestMultipleMountsFiltered(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
	readHook := testKprobeObjectFileWriteFilteredHook(pidStr, "/tmp4/tmp5")
	if kernels.EnableLargeProgs() {
		readHook = testKprobeObjectFileWriteFilteredHook(pidStr, "/tmp2/tmp3/tmp4/tmp5")
	}
	testMultipleMountsFiltered(t, readHook)
}

func TestMultiplePathComponents(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
	readHook := testKprobeObjectFileWriteHook(pidStr)
	testMultiplePathComponentsFiltered(t, readHook)
}

func TestMultipleMountPath(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
	readHook := testKprobeObjectFileWriteHook(pidStr)
	testMultipleMountPathFiltered(t, readHook)
}

func TestMultipleMountPathFiltered(t *testing.T) {
	pidStr := strconv.Itoa(int(GetMyPid()))
	// Kernel adds a & in the case of unresolved path. In the userspace we change that to [P]
	readHook := testKprobeObjectFileWriteFilteredHook(pidStr, "/tmp4/tmp5/&/6/7/8/9/10/11/12/13/14/15/16")
	if kernels.EnableLargeProgs() {
		readHook = testKprobeObjectFileWriteFilteredHook(pidStr, "/tmp2/tmp3/tmp4/tmp5/0/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16")
	}
	testMultipleMountPathFiltered(t, readHook)
}
