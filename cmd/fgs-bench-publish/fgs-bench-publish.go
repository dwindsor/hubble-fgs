package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/isovalent/hubble-fgs/pkg/bench"
	"google.golang.org/api/option"
	"google.golang.org/api/sheets/v4"
)

const (
	SHEET_ID = "1_5wv5gFcw6fh8FtJN8X1JB6iZJ85OlvM4eXuUXIHKo0"
)

func sheetName(summary *bench.BenchSummary) string {
	mode := strings.ToUpper(summary.Args.Mode)
	if summary.Args.Baseline {
		return "Baseline (" + mode + ")"
	} else if summary.Args.FgsEnableTls {
		return "FGS (" + mode + ", bpf-tls)"
	} else {
		return "FGS (" + mode + ", no-bpf-tls)"
	}
}

func main() {
	if len(os.Args) < 4 {
		log.Fatalf("usage: %s <git revision> <service agent key> <benchmark result>...\n", os.Args[0])
	}

	gitRev := os.Args[1]
	saKey := os.Args[2]

	for _, file := range os.Args[3:] {
		var summary bench.BenchSummary
		f, err := os.Open(file)
		if err != nil {
			log.Fatalf("Unable to open %s: %s", file, err)
		}
		dec := json.NewDecoder(f)
		err = dec.Decode(&summary)
		if err != nil {
			log.Fatalf("Unable to decode %s: %s", file, err)
		}
		f.Close()

		sheet := sheetName(&summary)
		if sheet != "" {
			PublishToSheets(gitRev, saKey, sheet, &summary)
		}
	}
}

func durationToSecs(d time.Duration) float64 {
	return float64(d) / float64(time.Second)
}

func getBpfStatForSheets(name string, s *bench.BenchSummary) float64 {
	for _, stat := range s.BpfStats {
		if stat.Name == name {
			if stat.RunCnt > 0 {
				return float64(time.Duration(stat.RunNs/stat.RunCnt)) / float64(time.Microsecond)
			} else {
				return 0.0
			}
		}
	}
	return 0.0
}

func utsnameToString(chars [65]int8) string {
	runes := make([]rune, len(chars))
	for i, c := range(chars) {
		if c == 0 {
			break
		}
		runes[i] = rune(c)
	}
	return string(runes)
}

func getSystemVersions() string {
	goVersion := runtime.Version()
	var utsname syscall.Utsname
	err := syscall.Uname(&utsname)
	var osVersion string
	if err != nil {
		osVersion = "(error)"
	} else {
		osVersion = utsnameToString(utsname.Release)
	}
	return fmt.Sprintf("%s / %s-%s", goVersion, utsnameToString(utsname.Sysname), osVersion)
}

func getCpuName() string {
	// The internal/sysinfo package would have this, but likely best not to
	// rely on an internal unstable API.
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return "unknown"
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "model name") {
			i := strings.Index(line, ": ")
			if i >= 0 {
				return line[i+2:]
			}
		}
	}
	return "unknown"
}

func PublishToSheets(gitRev, saKey, sheetName string, summary *bench.BenchSummary) {
	ctx := context.Background()
	sheetsService, err := sheets.NewService(ctx, option.WithCredentialsJSON([]byte(saKey)))
	if err != nil {
		log.Fatalf("NewService error: %s", err)
	}

	fgsSystemCpuPercent := 100.0 * float64(summary.FgsCpuUsage.SystemTime) / float64(summary.TestDurationNanos)
	fgsUserCpuPercent := 100.0 * float64(summary.FgsCpuUsage.UserTime) / float64(summary.TestDurationNanos)

	sourceSystemCpuPercent := 100.0 * float64(summary.SourceCpuUsage.SystemTime) / float64(summary.TestDurationNanos)
	sourceUserCpuPercent := 100.0 * float64(summary.SourceCpuUsage.UserTime) / float64(summary.TestDurationNanos)

	sinkSystemCpuPercent := 100.0 * float64(summary.SinkCpuUsage.SystemTime) / float64(summary.TestDurationNanos)
	sinkUserCpuPercent := 100.0 * float64(summary.SinkCpuUsage.UserTime) / float64(summary.TestDurationNanos)

	vr := sheets.ValueRange{
		Values: [][]interface{}{
			{
				summary.StartTime.Format(time.RFC3339),
				durationToSecs(summary.SetupDurationNanos),
				durationToSecs(summary.TestDurationNanos),
				summary.SourceStats.ActualRate,
				fgsSystemCpuPercent,
				fgsUserCpuPercent,
				summary.FgsCpuUsage.MaxRss,
				sourceSystemCpuPercent,
				sourceUserCpuPercent,
				sinkSystemCpuPercent,
				sinkUserCpuPercent,
				getBpfStatForSheets("event_sys_liste", summary),
				getBpfStatForSheets("event_ret_ipv4_", summary),
				getBpfStatForSheets("event_ipv4_conn", summary),
				getBpfStatForSheets("bpf_sockmap", summary),
				getBpfStatForSheets("bpf_skskb_verdi", summary),
				getBpfStatForSheets("bpf_skskb_parse", summary),
				getBpfStatForSheets("bpf_sk_msg_fgs", summary),
				gitRev,
				getSystemVersions(),
				getCpuName(),
			},
		},
	}

	result, err := sheetsService.Spreadsheets.Values.Append(SHEET_ID, sheetName+"!A1", &vr).ValueInputOption("RAW").Do()
	if err != nil {
		log.Fatalf("Append failed: %s", err)
	}

	log.Printf("Appended row: %v\n", result.TableRange)
}
