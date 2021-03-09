package observer

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/covalentio/hubble-fgs/api/v1/fgs"
	"github.com/golang/protobuf/jsonpb"
)

var (
	retryDelay = 2 * time.Second
)

func compareProcess(a, b *fgs.Process) bool {

	if a == nil && b == nil {
		return true
	} else if a == nil || b == nil {
		fmt.Printf("compareProcess: a=%p b=%p\n", a, b)
		return false
	}

	if b.Pid != nil && b.Pid.Value != 0 && a.Pid.Value != b.Pid.Value {
		fmt.Printf("compareProcess (%s): expected pid %d found pid %d\n",
			a.Binary, b.Pid.Value, a.Pid.Value)
		return false
	}
	if b.Binary != "" && strings.Contains(a.Binary, b.Binary) == false {
		return false
	}
	if b.Arguments != "" && strings.Contains(a.Arguments, b.Arguments) == false {
		return false
	}
	if b.Cwd != "" && strings.Contains(a.Cwd, b.Cwd) == false {
		fmt.Printf("compareProcess (%s): expected Cwd %s found Cwd %s\n",
			a.Binary, b.Cwd, a.Cwd)
		//return false
	}
	if b.Docker != "" && a.Docker != b.Docker {
		return false
	}
	return true
}

func jsonTestCompareExecve(a, b *fgs.GetEventsResponse_ProcessExec) bool {
	aExecve := a.ProcessExec
	bExecve := b.ProcessExec

	if ok := compareProcess(aExecve.Process, bExecve.Process); !ok {
		return false
	}
	if ok := compareProcess(aExecve.Parent, bExecve.Parent); !ok {
		return false
	}
	return true
}

func jsonTestCompareConnect(a, b *fgs.GetEventsResponse_ProcessConnect) bool {
	aConnect := a.ProcessConnect
	bConnect := b.ProcessConnect

	if ok := compareProcess(aConnect.Process, bConnect.Process); !ok {
		return false
	}
	if ok := compareProcess(aConnect.Parent, bConnect.Parent); !ok {
		return false
	}
	if bConnect.DestinationIp != "" && bConnect.DestinationIp != aConnect.DestinationIp {
		fmt.Printf("compareConnect (%s): expected destIP %s found destIp %s\n",
			aConnect.Process.Binary, bConnect.DestinationIp, aConnect.DestinationIp)
		return false
	}
	if bConnect.SourceIp != "" && bConnect.SourceIp != aConnect.SourceIp {
		fmt.Printf("compareConnect (%s): expected sourceIP %s found sourceIp %s\n",
			aConnect.Process.Binary, bConnect.SourceIp, aConnect.SourceIp)
		return false
	}
	if bConnect.DestinationPort != nil &&
		bConnect.DestinationPort.Value != 0 &&
		aConnect.DestinationPort.Value != bConnect.DestinationPort.Value {
		fmt.Printf("compareConnect (%s): expect source port %d found source port %d",
			aConnect.Process.Binary, bConnect.DestinationPort.Value, aConnect.DestinationPort.Value)
		return false
	}
	if bConnect.SourcePort != nil &&
		bConnect.SourcePort.Value != 0 &&
		aConnect.SourcePort.Value != bConnect.SourcePort.Value {
		fmt.Printf("compareConnec (%s): expect source port %d found source port %d",
			aConnect.Process.Binary, bConnect.SourcePort.Value, aConnect.SourcePort.Value)
		return false
	}
	return true
}

func jsonTestCompareListen(a, b *fgs.GetEventsResponse_ProcessListen) bool {
	aListen := a.ProcessListen
	bListen := b.ProcessListen

	if ok := compareProcess(aListen.Process, bListen.Process); !ok {
		return false
	}
	if ok := compareProcess(aListen.Parent, bListen.Parent); !ok {
		return false
	}
	if bListen.Ip != "" && bListen.Ip != aListen.Ip {
		fmt.Printf("compareListen: expected IP %s found Ip %s\n",
			bListen.Ip, aListen.Ip)
		return false
	}
	if bListen.Port != nil &&
		bListen.Port.Value != 0 &&
		aListen.Port.Value != bListen.Port.Value {
		fmt.Printf("compareListen: expect port %d found port %d",
			bListen.Port.Value, aListen.Port.Value)
		return false
	}
	return true
}

func jsonTestCompareAccept(a, b *fgs.GetEventsResponse_ProcessAccept) bool {
	aAccept := a.ProcessAccept
	bAccept := b.ProcessAccept

	if ok := compareProcess(aAccept.Process, bAccept.Process); !ok {
		return false
	}
	if ok := compareProcess(aAccept.Parent, bAccept.Parent); !ok {
		return false
	}
	if bAccept.SourceIp != "" && bAccept.SourceIp != aAccept.SourceIp {
		fmt.Printf("compareListen: expected IP %s found Ip %s\n",
			bAccept.SourceIp, aAccept.SourceIp)
		return false
	}
	if bAccept.SourcePort != nil &&
		bAccept.SourcePort.Value != 0 &&
		aAccept.SourcePort.Value != bAccept.SourcePort.Value {
		fmt.Printf("compareListen: expect port %d found port %d",
			bAccept.SourcePort.Value, aAccept.SourcePort.Value)
		return false
	}
	return true
}

func jsonTestCompareClose(a, b *fgs.GetEventsResponse_ProcessClose) bool {
	aClose := a.ProcessClose
	bClose := b.ProcessClose

	if ok := compareProcess(aClose.Process, bClose.Process); !ok {
		return false
	}
	if ok := compareProcess(aClose.Parent, bClose.Parent); !ok {
		return false
	}
	if bClose.SourceIp != "" && bClose.SourceIp != aClose.SourceIp {
		fmt.Printf("compareClose: expected IP %s found Ip %s\n",
			bClose.SourceIp, aClose.SourceIp)
		return false
	}
	if bClose.SourcePort != nil &&
		bClose.SourcePort.Value != 0 &&
		aClose.SourcePort.Value != bClose.SourcePort.Value {
		fmt.Printf("compareClose: expect port %d found port %d",
			bClose.SourcePort.Value, aClose.SourcePort.Value)
		return false
	}
	if bClose.DestinationIp != "" && bClose.DestinationIp != aClose.DestinationIp {
		fmt.Printf("compareClose: expected IP %s found Ip %s\n",
			bClose.DestinationIp, aClose.DestinationIp)
		return false
	}
	if bClose.DestinationPort != nil &&
		bClose.DestinationPort.Value != 0 &&
		aClose.DestinationPort.Value != bClose.DestinationPort.Value {
		fmt.Printf("compareClose: expect port %d found port %d",
			bClose.DestinationPort.Value, aClose.DestinationPort.Value)
		return false
	}
	return true
}
func jsonTestCompareTls(a, b *fgs.GetEventsResponse_Tls) bool {
	aTls := a.Tls
	bTls := b.Tls

	if ok := compareProcess(aTls.Process, bTls.Process); !ok {
		return false
	}
	if bTls.NegotiatedVersion != "" && bTls.NegotiatedVersion != aTls.NegotiatedVersion {
		fmt.Printf("compareTls: expected NegotiatedVersion %s found NegotiatedVersion %s\n",
			bTls.NegotiatedVersion, aTls.NegotiatedVersion)
		return false
	}
	if bTls.SupportedVersions != "" && bTls.SupportedVersions != aTls.SupportedVersions {
		fmt.Printf("compareTls: expected SupportedVersion %s found SupportedVersion %s\n",
			bTls.SupportedVersions, aTls.SupportedVersions)
		return false
	}
	if bTls.ClientVersion != "" && bTls.ClientVersion != a.Tls.ClientVersion {
		fmt.Printf("compareTls: expect ClientVersion %s found ClientVersion %s",
			bTls.ClientVersion, aTls.ClientVersion)
		return false
	}
	if bTls.SniName != "" && strings.Contains(bTls.SniName, aTls.SniName) == false {
		fmt.Printf("compareTls: expected SniName %s found SniName %s",
			bTls.SniName, bTls.SniName)
		return false
	}
	if bTls.SniType != "" && bTls.SniType != aTls.SniType {
		fmt.Printf("compareTls: expected SniType %s found SniType %s",
			bTls.SniType, bTls.SniType)
		return false
	}

	if bTls.ClientFlags != aTls.ClientFlags {
		fmt.Printf("compareTls: expected ClientFlags %s found ClientFlags %s",
			bTls.ClientFlags, bTls.ClientFlags)
		return false
	}

	if bTls.ServerFlags != aTls.ServerFlags {
		fmt.Printf("compareTls: expected ServerFlags %s found ServerFlags %s",
			bTls.ServerFlags, bTls.ServerFlags)
		return false
	}

	if len(bTls.Certificates) > 0 {
		if len(bTls.Certificates) != len(aTls.Certificates) {
			return false
		}
		for i, c := range bTls.Certificates {
			if c != aTls.Certificates[i] {
				return false
			}
		}
	}

	return true
}

func compareKprobeFunction(a, b *fgs.ProcessKprobe) bool {
	if a.FunctionName != b.FunctionName {
		return false
	}

	for i, rarg := range b.Args {
		switch ev := rarg.Arg.(type) {
		case *fgs.KprobeArgument_IntArg:
			switch expected := a.Args[i].Arg.(type) {
			case *fgs.KprobeArgument_IntArg:
				if ev.IntArg != expected.IntArg {
					fmt.Printf("compare.IntArg(%d): expected %d found %d\n",
						i, ev.IntArg, expected.IntArg)
					return false
				}
			default:
				fmt.Printf("compare.IntArg(%d): expected IntArg type\n", i)
				return false
			}
		case *fgs.KprobeArgument_StringArg:
			switch expected := a.Args[i].Arg.(type) {
			case *fgs.KprobeArgument_StringArg:
				if ev.StringArg != expected.StringArg {
					fmt.Printf("compare.StringArg(%d): expected \"%s\" found \"%s\"\n",
						i, ev.StringArg, expected.StringArg)
					return false
				}
			default:
				fmt.Printf("compare.StringArg(%d): expected StringArg type\n", i)
				return false
			}
		case *fgs.KprobeArgument_SizeArg:
			switch expected := a.Args[i].Arg.(type) {
			case *fgs.KprobeArgument_SizeArg:
				if ev.SizeArg != expected.SizeArg {
					fmt.Printf("compare.SizeArg(%d): expected %d found %d\n",
						i, ev.SizeArg, expected.SizeArg)
					return false
				}
			default:
				fmt.Printf("compare.SizeArg(%d): expected SizeArg type\n", i)
				return false
			}
		}
	}
	return true
}

func jsonTestCompareKprobe(a, b *fgs.ProcessKprobe) bool {
	if a.Process == nil || b.Process == nil {
		return false
	}
	if ok := compareProcess(a.Process, b.Process); !ok {
		return false
	}
	if ok := compareProcess(a.Parent, b.Parent); !ok {
		return false
	}
	if ok := compareKprobeFunction(a, b); !ok {
		return false
	}
	return true
}

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
	default:
		return fmt.Sprintf("<UNKNOWN:%T>", ev)
	}
}

func verbosePrintf(s string) {
	if Verbosity > 0 {
		fmt.Printf(s)
	}
}

type EventResponses []fgs.GetEventsResponse
type ByTime struct{ EventResponses }

func (s EventResponses) Len() int      { return len(s) }
func (s EventResponses) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s ByTime) Less(i, j int) bool {

	t1 := s.EventResponses[i].Time
	t2 := s.EventResponses[j].Time
	t1s := t1.GetSeconds()
	t2s := t2.GetSeconds()
	if t1s == t2s {
		return t1.GetNanos() < t2.GetNanos()
	}
	return t1s < t2s
}

func jsonTestCompare(trace []*fgs.GetEventsResponse, jsonFile *os.File, attempts, found int) bool {
	var err error

	if attempts < 1 {
		return false
	}

	if jsonFile == nil {
		fmt.Printf("jsonTestCompare: openning: %s\n", exportFile)
		jsonFile, err = os.Open(exportFile)
		if err != nil {
			return false
		}
		defer jsonFile.Close()
	}

	events := make([]fgs.GetEventsResponse, 0, 128)
	dec := json.NewDecoder(jsonFile)
	for {
		ev := fgs.GetEventsResponse{}
		err = jsonpb.UnmarshalNext(dec, &ev)
		if err != nil {
			break
		}
		events = append(events, ev)
		if !dec.More() {
			break
		}
	}
	sort.Stable(ByTime{events})

	evidx := 0
	for tidx, t := range trace[found:] {
		for {
			if evidx == len(events) {
				goto retry
			}
			ev := events[evidx]
			evidx += 1

			evTyStr := eventTypeString(ev.Event)
			trTyStr := eventTypeString(t.Event)
			if Verbosity > 0 {
				fmt.Printf("tidx=%d found=%d => got %s looking for %s\n", tidx, found, evTyStr, trTyStr)
			}
			switch res := ev.Event.(type) {
			case *fgs.GetEventsResponse_ProcessConnect:
				switch bRes := t.Event.(type) {
				case *fgs.GetEventsResponse_ProcessConnect:
					if ok := jsonTestCompareConnect(res, bRes); ok {
						found++
						verbosePrintf("\tFOUND IT!\n")
						goto next
					}
				}
			case *fgs.GetEventsResponse_ProcessExec:
				switch bRes := t.Event.(type) {
				case *fgs.GetEventsResponse_ProcessExec:
					if ok := jsonTestCompareExecve(res, bRes); ok {
						found++
						verbosePrintf("\tFOUND IT!\n")
						goto next
					}
				}
			case *fgs.GetEventsResponse_ProcessListen:
				switch bRes := t.Event.(type) {
				case *fgs.GetEventsResponse_ProcessListen:
					if ok := jsonTestCompareListen(res, bRes); ok {
						found++
						verbosePrintf("\tFOUND IT!\n")
						goto next
					}
				}
			case *fgs.GetEventsResponse_ProcessAccept:
				switch bRes := t.Event.(type) {
				case *fgs.GetEventsResponse_ProcessAccept:
					if ok := jsonTestCompareAccept(res, bRes); ok {
						found++
						verbosePrintf("\tFOUND IT!\n")
						goto next
					}
				}
			case *fgs.GetEventsResponse_Tls:
				switch bRes := t.Event.(type) {
				case *fgs.GetEventsResponse_Tls:
					if ok := jsonTestCompareTls(res, bRes); ok {
						found++
						verbosePrintf("\tFOUND IT!\n")
						goto next
					}
				}
			case *fgs.GetEventsResponse_ProcessExit:
			case *fgs.GetEventsResponse_ProcessClose:
				switch bRes := t.Event.(type) {
				case *fgs.GetEventsResponse_ProcessClose:
					if ok := jsonTestCompareClose(res, bRes); ok {
						found++
						verbosePrintf("\tFOUND IT!\n")
						goto next
					}
				}
			case *fgs.GetEventsResponse_ProcessKprobe:
				switch bRes := t.Event.(type) {
				case *fgs.GetEventsResponse_ProcessKprobe:
					if ok := jsonTestCompareKprobe(res.ProcessKprobe, bRes.ProcessKprobe); ok {
						found++
						verbosePrintf("\tFOUND IT!\n")
						goto next
					}
				}
			case *fgs.GetEventsResponse_Test:
				switch t.Event.(type) {
				case *fgs.GetEventsResponse_Test:
					found++
					verbosePrintf("\tFOUND IT!\n")
					goto next
				}

			default:
				verbosePrintf("unknown\n")
			}
		}
	next:
	}

	if found == len(trace) {
		verbosePrintf("\tFOUND ALL!\n")
		return true
	}
retry:
	attempts--
	time.Sleep(retryDelay)
	return jsonTestCompare(trace, jsonFile, attempts, found)
}
