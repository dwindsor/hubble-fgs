//go:build !windows

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"

	"google.golang.org/api/option"
	"google.golang.org/api/sheets/v4"

	"github.com/isovalent/hubble-fgs/pkg/bench"
)

const (
	SHEET_DOC_ID = "1_5wv5gFcw6fh8FtJN8X1JB6iZJ85OlvM4eXuUXIHKo0"

	DERIVED_DATA_SHEET_ID = 97836020
)

// Sheet identifiers (see gid= in URL).
// Used as the BatchUpdate requests work on the id instead of the name.
var testNameToSheetId = map[string]int64{
	"TestBenchBaseline/tls-crr":     503947610,
	"TestBenchBaseline/netperf-crr": 371755781,
	"TestBenchBaseline/http-crr-go": 78820048,

	"TestFGSNoTLS/tls-crr":     1814748783,
	"TestFGSNoTLS/netperf-crr": 2060975911,
	"TestFGSNoTls/http-crr-go": 1585471493,

	"TestFGSTLS/tls-crr":     2026607124,
	"TestFGSTLS/netperf-crr": 839882648,
	"TestFGSTLS/http-crr-go": 1872945073,

	"TestFGSTLS/netperf-rr":        1072107619,
	"TestBenchBaseline/netperf-rr": 2098922345,

	"TestBenchBaseline/http-rr-go": 1043261075,
	"TestFGSTLS/http-rr-go":        794354699,

	"TestEnvoyOverhead": 14732349,
}

func summaryToSheetId(summary *bench.Summary) int64 {
	if id, ok := testNameToSheetId[summary.Args.TestName]; ok {
		return id
	}
	log.Printf("No sheet for %s, defaulting to 'Test'\n", summary.Args.TestName)
	return 0 // Test sheet
}

func main() {
	if len(os.Args) < 5 {
		log.Fatalf("usage: %s (publish|pretty) <git revision> <service agent key> <benchmark result>...", os.Args[0])
	}

	cmd := os.Args[1]
	gitRev := os.Args[2]
	saKey := os.Args[3]

	ctx := context.Background()
	sheetsService, err := sheets.NewService(
		ctx,
		option.WithAuthCredentialsJSON(option.ServiceAccount, []byte(saKey)),
	)
	if err != nil {
		log.Fatalf("NewService error: %s", err)
	}

	summaries := make(map[string]*bench.Summary)
	for _, file := range os.Args[4:] {
		var summary bench.Summary
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
		summaries[summary.Args.TestName] = &summary
	}

	switch cmd {
	case "publish":
		for _, summary := range summaries {
			publishToSheets(sheetsService, gitRev, summary)
		}
	case "pretty":
		prettyPrintForPR(sheetsService, gitRev, summaries)
	default:
		log.Fatalf("Unknown command '%s', expected 'publish' or 'pretty'", cmd)
	}
}

func durationToSecs(d time.Duration) float64 {
	return float64(d) / float64(time.Second)
}

func getBpfStatForSheets(name string, s *bench.Summary) float64 {
	for _, stat := range s.BpfStats {
		if stat.Name == name {
			if stat.RunCnt > 0 {
				return float64(time.Duration(stat.RunNs/stat.RunCnt)) / float64(time.Microsecond)
			}
			return 0.0
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

func getCPUName() string {
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
			_, after, ok := strings.Cut(line, ": ")
			if ok {
				return after
			}
		}
	}
	return "unknown"
}

func valueToCellData(value any) *sheets.CellData {
	ev := &sheets.ExtendedValue{}
	switch v := value.(type) {
	case string:
		*ev.StringValue = v
	case bool:
		*ev.BoolValue = v
	case int64:
		*ev.NumberValue = float64(v)
	case float64:
		if math.IsInf(v, 1) {
			*ev.StringValue = "+Inf"
		} else if math.IsInf(v, -1) {
			*ev.StringValue = "-Inf"
		} else if math.IsNaN(v) {
			*ev.StringValue = "NaN"
		} else {
			*ev.NumberValue = v
		}
	default:
		log.Fatalf("cannot format value: %v", value)
	}
	return &sheets.CellData{UserEnteredValue: ev}
}

func valuesFromSummary(gitRev string, summary *bench.Summary) []*sheets.CellData {
	fgsSystemCPUPercent := 100.0 * float64(summary.FgsCPUUsage.SystemTime) / float64(summary.TestDurationNanos)
	fgsUserCPUPercent := 100.0 * float64(summary.FgsCPUUsage.UserTime) / float64(summary.TestDurationNanos)

	sourceSystemCPUPercent := 100.0 * float64(summary.SourceStats.CPUUsage.SystemTime) / float64(summary.TestDurationNanos)
	sourceUserCPUPercent := 100.0 * float64(summary.SourceStats.CPUUsage.UserTime) / float64(summary.TestDurationNanos)

	sinkSystemCPUPercent := 100.0 * float64(summary.SinkStats.CPUUsage.SystemTime) / float64(summary.TestDurationNanos)
	sinkUserCPUPercent := 100.0 * float64(summary.SinkStats.CPUUsage.UserTime) / float64(summary.TestDurationNanos)

	if summary.Args.Source.IsRequestResponse() {
		return []*sheets.CellData{
			valueToCellData(summary.StartTime.Format(time.RFC3339)),
			valueToCellData(durationToSecs(summary.SetupDurationNanos)),
			valueToCellData(durationToSecs(summary.TestDurationNanos)),

			// Rates and latencies
			valueToCellData(summary.SourceStats.ActualRate),
			valueToCellData(durationToSecs(summary.SourceStats.LatencyP50)),
			valueToCellData(durationToSecs(summary.SourceStats.LatencyP90)),
			valueToCellData(durationToSecs(summary.SourceStats.LatencyP99)),

			// Resource usage
			valueToCellData(fgsSystemCPUPercent),
			valueToCellData(fgsUserCPUPercent),
			valueToCellData(summary.FgsCPUUsage.MaxRss),
			valueToCellData(sourceSystemCPUPercent),
			valueToCellData(sourceUserCPUPercent),
			valueToCellData(sinkSystemCPUPercent),
			valueToCellData(sinkUserCPUPercent),

			// BPF stats
			valueToCellData(getBpfStatForSheets("event_sys_liste", summary)),
			valueToCellData(getBpfStatForSheets("event_ret_ipv4_", summary)),
			valueToCellData(getBpfStatForSheets("event_ipv4_conn", summary)),
			valueToCellData(getBpfStatForSheets("bpf_sockmap", summary)),
			valueToCellData(getBpfStatForSheets("bpf_skskb_verdi", summary)),
			valueToCellData(getBpfStatForSheets("bpf_skskb_parse", summary)),
			valueToCellData(getBpfStatForSheets("bpf_sk_msg_fgs", summary)),

			// Meta
			valueToCellData(gitRev),
			valueToCellData(getSystemVersions()),
			valueToCellData(getCPUName()),
		}
	}
	return []*sheets.CellData{
		valueToCellData(summary.StartTime.Format(time.RFC3339)),
		valueToCellData(durationToSecs(summary.SetupDurationNanos)),
		valueToCellData(durationToSecs(summary.TestDurationNanos)),
		valueToCellData(summary.SourceStats.ActualRate),

		// Resource usage
		valueToCellData(fgsSystemCPUPercent),
		valueToCellData(fgsUserCPUPercent),
		valueToCellData(summary.FgsCPUUsage.MaxRss),
		valueToCellData(sourceSystemCPUPercent),
		valueToCellData(sourceUserCPUPercent),
		valueToCellData(sinkSystemCPUPercent),
		valueToCellData(sinkUserCPUPercent),

		// BPF stats
		valueToCellData(getBpfStatForSheets("event_sys_liste", summary)),
		valueToCellData(getBpfStatForSheets("event_ret_ipv4_", summary)),
		valueToCellData(getBpfStatForSheets("event_ipv4_conn", summary)),
		valueToCellData(getBpfStatForSheets("bpf_sockmap", summary)),
		valueToCellData(getBpfStatForSheets("bpf_skskb_verdi", summary)),
		valueToCellData(getBpfStatForSheets("bpf_skskb_parse", summary)),
		valueToCellData(getBpfStatForSheets("bpf_sk_msg_fgs", summary)),

		// Meta
		valueToCellData(gitRev),
		valueToCellData(getSystemVersions()),
		valueToCellData(getCPUName()),
	}

}

func publishToSheets(sheetsService *sheets.Service, gitRev string, summary *bench.Summary) {

	sheetId := summaryToSheetId(summary)
	values := valuesFromSummary(gitRev, summary)

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
						EndColumnIndex:   1 + int64(len(values)),
					},
					Rows: []*sheets.RowData{{Values: values}},
				},
			},
		},
	}

	_, err := sheetsService.Spreadsheets.BatchUpdate(SHEET_DOC_ID, &r).Do()
	if err != nil {
		log.Fatalf("BatchUpdate of %s failed: %s", summary.Args.TestName, err)
	}

	log.Printf("Append to %s / %d OK.\n", SHEET_DOC_ID, sheetId)
}

func getDerivedDataColumn(sheetsService *sheets.Service, column string) float64 {
	resp, err := sheetsService.Spreadsheets.Values.Get(SHEET_DOC_ID,
		fmt.Sprintf("Derived Data!%s2:%s2", column, column)).Do()

	if err != nil {
		log.Fatalf("Failed to retrieve derived data value: %s", err)
	}

	f, err := strconv.ParseFloat(strings.TrimRight(fmt.Sprintf("%s", resp.Values[0][0]), "%"), 64)
	if err != nil {
		log.Fatalf("Failed to parse derived data value: %s", err)
	}
	return f
}

func getRatePercent(testA, testB string, summaries map[string]*bench.Summary) float64 {
	sumA, okA := summaries[testA]
	sumB, okB := summaries[testB]
	if !okA || !okB {
		log.Fatalf("%s or %s not found", testA, testB)
	}
	return 100.0 * sumA.SourceStats.ActualRate / sumB.SourceStats.ActualRate
}

const prCommentTemplate = `Benchmark results ({{.GitRev}}):
- TLS connection rate with FGS (tls enabled) vs baseline: {{.TLSCrrPercent}}%
- TCP connection rate with FGS (tls enabled) vs baseline: {{.TCPCrrPercent}}% (vs master: {{.TCPCrrPercentDiff}}%)
- TCP request response rate with FGS (no tls) vs baseline: {{.TCPRrPercent}}%
- TCP request response rate with FGS (tls enabled) vs baseline: {{.TCPTLSRrPercent}}%
`

type PRCommentData struct {
	GitRev            string
	TLSCrrPercent     string
	TCPCrrPercent     string
	TCPCrrPercentDiff string
	TCPRrPercent      string
	TCPTLSRrPercent   string
}

// Pretty-print the benchmark results for the PR comment that includes the difference to the latest
// nightly run.
func prettyPrintForPR(sheetsService *sheets.Service, gitRev string, summaries map[string]*bench.Summary) {
	fmtFloat := func(f float64) string {
		return fmt.Sprintf("%.1f", f)
	}

	tcpCrrPercent := getRatePercent("TestFGSTLS/netperf-crr", "TestBenchBaseline/netperf-crr", summaries)
	// FIXME: temporarily disabled
	// tlsCrrPercent := getRatePercent("TestFGSTLS/tls-crr", "TestBenchBaseline/tls-crr", summaries)
	tcpRrPercent := getRatePercent("TestFGSNoTLS/netperf-rr", "TestBenchBaseline/netperf-rr", summaries)
	tcpTLSRrPercent := getRatePercent("TestFGSTLS/netperf-rr", "TestBenchBaseline/netperf-rr", summaries)
	masterTCPCrrPercent := getDerivedDataColumn(sheetsService, "C")
	tcpCrrPercentDiff := fmtFloat(masterTCPCrrPercent - tcpCrrPercent)
	if masterTCPCrrPercent-tcpCrrPercent >= 0.0 {
		tcpCrrPercentDiff = "+" + tcpCrrPercentDiff
	}

	tmpl := strings.ReplaceAll(prCommentTemplate, "%", "%25")
	tmpl = strings.ReplaceAll(tmpl, "\n", "%0A")

	fmt.Print("::set-output name=body::")

	err := template.Must(template.New("comment").Parse(tmpl)).Execute(os.Stdout,
		PRCommentData{
			GitRev: gitRev,
			// TLSCrrPercent:     fmtFloat(tlsCrrPercent),
			TLSCrrPercent:     "temporarily disabled",
			TCPCrrPercent:     fmtFloat(tcpCrrPercent),
			TCPCrrPercentDiff: tcpCrrPercentDiff,
			TCPRrPercent:      fmtFloat(tcpRrPercent),
			TCPTLSRrPercent:   fmtFloat(tcpTLSRrPercent),
		})

	if err != nil {
		log.Fatal(err)
	}
}
