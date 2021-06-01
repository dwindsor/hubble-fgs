package observer

import (
	"context"
	"fmt"
	"io/ioutil"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"

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
	kprobe, err := getDefaultObserver(t, withConfig(testConfigFile))
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
	}
	initialSensor := kprobe.createInitialObserverSensor()
	kprobe.observerLoadSensor(context.TODO(), initialSensor)
	kprobe.RemovePrograms()
}

// NB: This is similar to TestKprobeObjectWriteRead, but it's a bit easier to
// debug because we can write things on stdout which will not generate events.
func TestKprobeLseek(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10000*time.Millisecond)
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

	kprobe, err := getDefaultObserverWithWatchers(t, withConfig(testConfigFile))
	if err != nil {
		t.Fatalf("getDefaultObserver error: %s", err)
	}
	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWG.Wait()
	fmt.Printf("Calling lseek...\n")
	unix.Seek(-1, 0, 4444)
	exitWG.Wait()
	testDone(t, kprobe)
}

func TestKprobeObjectWriteRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10000*time.Millisecond)
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

	arg0 := &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_IntArg{IntArg: 1}}
	arg1 := &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_BytesArg{BytesArg: []byte("hello world")}}
	arg2 := &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_SizeArg{SizeArg: 11}}

	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &fgs.ProcessKprobe{
					Process:      &fgs.Process{Binary: selfBinary},
					Parent:       &fgs.Process{Binary: ""},
					FunctionName: "__x64_sys_write",
					Args:         []*fgs.KprobeArgument{arg0, arg1, arg2},
				},
			},
		},
	}

	kprobe, err := getDefaultObserverWithWatchers(t, withConfig(testConfigFile))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWG.Wait()
	_, err = syscall.Write(1, []byte("hello world"))
	exitWG.Wait()
	retries := jsonRetries
	time.Sleep(1000 * time.Millisecond)
	if ok := JsonTestCompare(trace, nil, retries, 0); !ok {
		t.Fail()
	}
	testDone(t, kprobe)
}

func TestKprobeObjectRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10000*time.Millisecond)
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

	arg0 := &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_IntArg{IntArg: int32(fd2)}}
	arg1 := &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_BytesArg{BytesArg: []byte("hello world")}}
	arg2 := &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_SizeArg{SizeArg: 11}}
	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &fgs.ProcessKprobe{
					Process:      &fgs.Process{Binary: selfBinary},
					Parent:       &fgs.Process{Binary: ""},
					FunctionName: "__x64_sys_read",
					Args:         []*fgs.KprobeArgument{arg0, arg1, arg2},
				},
			},
		},
	}
	kprobe, err := getDefaultObserverWithWatchers(t, withConfig(testConfigFile))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
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
	retries := jsonRetries
	time.Sleep(1000 * time.Millisecond)
	if ok := JsonTestCompare(trace, nil, retries, 0); !ok {
		t.Fail()
	}
	testDone(t, kprobe)
}

// __x64_sys_openat trace
var (
	openArg0  = &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_IntArg{IntArg: -100}}
	openArg1  = &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_StringArg{StringArg: "/tmp/testfile"}}
	openTrace = []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &fgs.ProcessKprobe{
					Process:      &fgs.Process{Binary: selfBinary},
					Parent:       &fgs.Process{Binary: ""},
					FunctionName: "__x64_sys_openat",
					Args:         []*fgs.KprobeArgument{openArg0, openArg1},
				},
			},
		},
	}
)

func testKprobeObjectFiltered(t *testing.T,
	readHook string,
	trace []*fgs.GetEventsResponse,
	invertResult bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10000*time.Millisecond)
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

	kprobe, err := getDefaultObserverWithWatchers(t, withConfig(testConfigFile))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWG.Wait()
	fd2, errno := syscall.Open("/tmp/testfile", syscall.O_RDWR, 0x770)
	if fd2 < 0 {
		fmt.Printf("File open from read failed: %s\n", errno)
		t.Fatal()
	}
	syscall.Write(fd2, []byte("hello world"))
	exitWG.Wait()
	retries := jsonRetries
	time.Sleep(1000 * time.Millisecond)
	ok := JsonTestCompare(trace, nil, retries, 0)
	if (invertResult && ok) || (!invertResult && !ok) {
		t.Fail()
	}
	testDone(t, kprobe)
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
	testKprobeObjectFiltered(t, readHook, openTrace, false)
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
	testKprobeObjectFiltered(t, readHook, openTrace, false)
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
	testKprobeObjectFiltered(t, readHook, openTrace, true)
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
	testKprobeObjectFiltered(t, readHook, openTrace, true)
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
	testKprobeObjectFiltered(t, readHook, openTrace, false)
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
	testKprobeObjectFiltered(t, readHook, openTrace, false)
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
	ctx, cancel := context.WithTimeout(context.Background(), 10000*time.Millisecond)
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

	arg0 := &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_IntArg{IntArg: 1}}
	arg1 := &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_BytesArg{BytesArg: []byte("hello iovec world")}}

	trace := []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &fgs.ProcessKprobe{
					Process:      &fgs.Process{Binary: selfBinary},
					Parent:       &fgs.Process{Binary: ""},
					FunctionName: "__x64_sys_writev",
					Args:         []*fgs.KprobeArgument{arg0, arg1},
				},
			},
		},
	}

	kprobe, err := getDefaultObserverWithWatchers(t, withConfig(testConfigFile))
	if err != nil {
		t.Fatalf("getDefaultObserverWithWatchers error: %s", err)
	}
	loopEvents(t, &exitWG, &execWG, kprobe, ctx)
	execWG.Wait()
	err = helloIovecWorldWritev()
	execWG.Wait()
	retries := jsonRetries
	time.Sleep(1000 * time.Millisecond)
	if ok := JsonTestCompare(trace, nil, retries, 0); !ok {
		t.Fail()
	}
	testDone(t, kprobe)
}

var (
	doOpenTrace = []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &fgs.ProcessKprobe{
					Process:      &fgs.Process{Binary: selfBinary},
					Parent:       &fgs.Process{Binary: ""},
					FunctionName: "do_filp_open",
					Args:         []*fgs.KprobeArgument{openArg0, openArg1},
				},
			},
		},
	}
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
	testKprobeObjectFiltered(t, readHook, doOpenTrace, false)
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
	testKprobeObjectFiltered(t, readHook, doOpenTrace, false)
}

var (
	writeArg0 = &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_StringArg{StringArg: "/testfile/tmp"}}
	writeArg1 = &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_BytesArg{BytesArg: []byte("hello world")}}
	writeArg2 = &fgs.KprobeArgument{Arg: &fgs.KprobeArgument_SizeArg{SizeArg: 11}}

	writeFileTrace = []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &fgs.ProcessKprobe{
					Process:      &fgs.Process{Binary: selfBinary},
					Parent:       &fgs.Process{Binary: ""},
					FunctionName: "__x64_sys_write",
					Args:         []*fgs.KprobeArgument{writeArg0, writeArg1, writeArg2},
				},
			},
		},
	}
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
	testKprobeObjectFiltered(t, readHook, writeFileTrace, false)
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
        - "/testfile/tmp"
`
	testKprobeObjectFiltered(t, readHook, writeFileTrace, false)
}
