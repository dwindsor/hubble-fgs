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
	SHEET_DOC_ID = "1_5wv5gFcw6fh8FtJN8X1JB6iZJ85OlvM4eXuUXIHKo0"

	SHEET_BASELINE_TLS  = 503947610
	SHEET_BASELINE_TCP  = 371755781
	SHEET_BASELINE_HTTP = 78820048

	SHEET_FGS_TLS_TLS  = 2026607124
	SHEET_FGS_TCP_TLS  = 839882648
	SHEET_FGS_HTTP_TLS = 1872945073

	SHEET_FGS_TLS_NOTLS  = 1814748783 
	SHEET_FGS_TCP_NOTLS  = 2060975911 
	SHEET_FGS_HTTP_NOTLS = 1585471493 
)

func summaryToSheetId(summary *bench.BenchSummary) int64 {
	if summary.Args.Baseline {
		switch summary.Args.Mode {
		case "tcp":
			return SHEET_BASELINE_TCP
		case "tls":
			return SHEET_BASELINE_TLS
		case "http":
			return SHEET_BASELINE_HTTP
		default:
			panic("unknown mode")
		}
	} else if summary.Args.FgsEnableTls {
		switch summary.Args.Mode {
		case "tcp":
			return SHEET_FGS_TCP_TLS
		case "tls":
			return SHEET_FGS_TLS_TLS
		case "http":
			return SHEET_FGS_HTTP_TLS
		default:
			panic("unknown mode")
		}
	} else {
		switch summary.Args.Mode {
		case "tcp":
			return SHEET_FGS_TCP_NOTLS
		case "tls":
			return SHEET_FGS_TLS_NOTLS
		case "http":
			return SHEET_FGS_HTTP_NOTLS
		default:
			panic("unknown mode")
		}
	}
}

func main() {
	if len(os.Args) < 4 {
		log.Fatalf("usage: %s <git revision> <service agent key> <benchmark result>...\n", os.Args[0])
	}

	gitRev := os.Args[1]
	saKey := os.Args[2]


	ctx := context.Background()
	sheetsService, err := sheets.NewService(ctx, option.WithCredentialsJSON([]byte(saKey)))
	if err != nil {
		log.Fatalf("NewService error: %s", err)
	}

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

		publishToSheets(sheetsService, gitRev, &summary)
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
	for i, c := range chars {
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

func valueToCellData(value interface{}) *sheets.CellData {
	ev := &sheets.ExtendedValue{}
	switch v := value.(type) {
	case string:
		ev.StringValue = v
	case bool:
		ev.BoolValue = v
	case int64:
		ev.NumberValue = float64(v)
	case float64:
		ev.NumberValue = float64(v)
	default:
		log.Fatalf("cannot format value: %v\n", value)
	}
	return &sheets.CellData{UserEnteredValue: ev}
}

func publishToSheets(sheetsService *sheets.Service, gitRev string, summary *bench.BenchSummary) {

	sheetId := summaryToSheetId(summary)

	fgsSystemCpuPercent := 100.0 * float64(summary.FgsCpuUsage.SystemTime) / float64(summary.TestDurationNanos)
	fgsUserCpuPercent := 100.0 * float64(summary.FgsCpuUsage.UserTime) / float64(summary.TestDurationNanos)

	sourceSystemCpuPercent := 100.0 * float64(summary.SourceCpuUsage.SystemTime) / float64(summary.TestDurationNanos)
	sourceUserCpuPercent := 100.0 * float64(summary.SourceCpuUsage.UserTime) / float64(summary.TestDurationNanos)

	sinkSystemCpuPercent := 100.0 * float64(summary.SinkCpuUsage.SystemTime) / float64(summary.TestDurationNanos)
	sinkUserCpuPercent := 100.0 * float64(summary.SinkCpuUsage.UserTime) / float64(summary.TestDurationNanos)

	values :=
		[]*sheets.CellData{
			valueToCellData(summary.StartTime.Format(time.RFC3339)),
			valueToCellData(durationToSecs(summary.SetupDurationNanos)),
			valueToCellData(durationToSecs(summary.TestDurationNanos)),
			valueToCellData(summary.SourceStats.ActualRate),
			valueToCellData(fgsSystemCpuPercent),
			valueToCellData(fgsUserCpuPercent),
			valueToCellData(summary.FgsCpuUsage.MaxRss),
			valueToCellData(sourceSystemCpuPercent),
			valueToCellData(sourceUserCpuPercent),
			valueToCellData(sinkSystemCpuPercent),
			valueToCellData(sinkUserCpuPercent),
			valueToCellData(getBpfStatForSheets("event_sys_liste", summary)),
			valueToCellData(getBpfStatForSheets("event_ret_ipv4_", summary)),
			valueToCellData(getBpfStatForSheets("event_ipv4_conn", summary)),
			valueToCellData(getBpfStatForSheets("bpf_sockmap", summary)),
			valueToCellData(getBpfStatForSheets("bpf_skskb_verdi", summary)),
			valueToCellData(getBpfStatForSheets("bpf_skskb_parse", summary)),
			valueToCellData(getBpfStatForSheets("bpf_sk_msg_fgs", summary)),
			valueToCellData(gitRev),
			valueToCellData(getSystemVersions()),
			valueToCellData(getCpuName()),
		}

	r := sheets.BatchUpdateSpreadsheetRequest{
		Requests: []*sheets.Request{
			// Insert a new empty row on top.
			{
				InsertDimension: &sheets.InsertDimensionRequest{
					Range: &sheets.DimensionRange{
						Dimension:  "ROWS",
						SheetId:    sheetId,
						StartIndex: 1,
						EndIndex:   2,
					},
				},
			},
			// Update the new row.
			{
				UpdateCells: &sheets.UpdateCellsRequest{
					Fields: "*",
					Range: &sheets.GridRange{
						SheetId:          sheetId,
						StartRowIndex:    1,
						EndRowIndex:      2,
						StartColumnIndex: 0,
						EndColumnIndex:   1+int64(len(values)),
					},
					Rows: []*sheets.RowData{{Values: values}},
				},
			},
		},
	}

	_, err := sheetsService.Spreadsheets.BatchUpdate(SHEET_DOC_ID, &r).Do()
	if err != nil {
		log.Fatalf("BatchUpdate failed: %s", err)
	}

	log.Printf("Append to %s / %d OK.\n", SHEET_DOC_ID, sheetId)
}
