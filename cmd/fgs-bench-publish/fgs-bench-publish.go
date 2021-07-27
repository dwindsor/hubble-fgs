package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"text/template"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/isovalent/hubble-fgs/pkg/bench"
	"google.golang.org/api/option"
	"google.golang.org/api/sheets/v4"
)

const (
	SHEET_DOC_ID = "1_5wv5gFcw6fh8FtJN8X1JB6iZJ85OlvM4eXuUXIHKo0"

	DERIVED_DATA_SHEET_ID = 97836020
)

// Sheet identifiers (see gid= in URL).
// Used as the BatchUpdate requests work on the id instead of the name.
var testNameToSheetId = map[string]int64{
	"BenchmarkBaseline/tls":  503947610,
	"BenchmarkBaseline/tcp":  371755781,
	"BenchmarkBaseline/http": 78820048,

	"BenchmarkFgsNoTls/tls":  1814748783,
	"BenchmarkFgsNoTls/tcp":  2060975911,
	"BenchmarkFgsNoTls/http": 1585471493,

	"BenchmarkFgsTls/tls":  2026607124,
	"BenchmarkFgsTls/tcp":  839882648,
	"BenchmarkFgsTls/http": 1872945073,

	"BenchmarkFgsTcpRequestResponse/tcp":  1072107619,
	"BenchmarkBaselineTcpRequestResponse": 2098922345,

	"BenchmarkBaselineHttpRequestResponse": 1043261075,
	"BenchmarkFgsHttpRequestResponse/http": 794354699,
}

func summaryToSheetId(summary *bench.BenchSummary) int64 {
	if id, ok := testNameToSheetId[summary.TestName]; ok {
		return id
	} else {
		log.Printf("No sheet for %s, defaulting to 'Test'\n", summary.TestName)
		return 0 // Test sheet
	}
}

func main() {
	if len(os.Args) < 5 {
		log.Fatalf("usage: %s (publish|pretty) <git revision> <service agent key> <benchmark result>...", os.Args[0])
	}

	cmd := os.Args[1]
	gitRev := os.Args[2]
	saKey := os.Args[3]

	ctx := context.Background()
	sheetsService, err := sheets.NewService(ctx, option.WithCredentialsJSON([]byte(saKey)))
	if err != nil {
		log.Fatalf("NewService error: %s", err)
	}

	summaries := make(map[string]*bench.BenchSummary)
	for _, file := range os.Args[4:] {
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
		summaries[summary.TestName] = &summary
	}

	if cmd == "publish" {
		for _, summary := range summaries {
			publishToSheets(sheetsService, gitRev, summary)
		}
	} else if cmd == "pretty" {
		prettyPrintForPR(sheetsService, gitRev, summaries)
	} else {
		log.Fatalf("Unknown command '%s', expected 'publish' or 'pretty'", cmd)
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
		log.Fatalf("cannot format value: %v", value)
	}
	return &sheets.CellData{UserEnteredValue: ev}
}

func valuesFromSummary(gitRev string, summary *bench.BenchSummary) []*sheets.CellData {

	fgsSystemCpuPercent := 100.0 * float64(summary.FgsCpuUsage.SystemTime) / float64(summary.TestDurationNanos)
	fgsUserCpuPercent := 100.0 * float64(summary.FgsCpuUsage.UserTime) / float64(summary.TestDurationNanos)

	sourceSystemCpuPercent := 100.0 * float64(summary.SourceCpuUsage.SystemTime) / float64(summary.TestDurationNanos)
	sourceUserCpuPercent := 100.0 * float64(summary.SourceCpuUsage.UserTime) / float64(summary.TestDurationNanos)

	sinkSystemCpuPercent := 100.0 * float64(summary.SinkCpuUsage.SystemTime) / float64(summary.TestDurationNanos)
	sinkUserCpuPercent := 100.0 * float64(summary.SinkCpuUsage.UserTime) / float64(summary.TestDurationNanos)

	if summary.Args.RequestResponse {
		return []*sheets.CellData{
			valueToCellData(summary.StartTime.Format(time.RFC3339)),
			valueToCellData(durationToSecs(summary.SetupDurationNanos)),
			valueToCellData(durationToSecs(summary.TestDurationNanos)),

			// Rates and latencies
			valueToCellData(summary.SourceStats.ActualReqRate),
			valueToCellData(durationToSecs(summary.SourceStats.LatencyP50)),
			valueToCellData(durationToSecs(summary.SourceStats.LatencyP90)),
			valueToCellData(durationToSecs(summary.SourceStats.LatencyP99)),

			// Resource usage
			valueToCellData(fgsSystemCpuPercent),
			valueToCellData(fgsUserCpuPercent),
			valueToCellData(summary.FgsCpuUsage.MaxRss),
			valueToCellData(sourceSystemCpuPercent),
			valueToCellData(sourceUserCpuPercent),
			valueToCellData(sinkSystemCpuPercent),
			valueToCellData(sinkUserCpuPercent),

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
			valueToCellData(getCpuName()),
		}
	} else {
		return []*sheets.CellData{
			valueToCellData(summary.StartTime.Format(time.RFC3339)),
			valueToCellData(durationToSecs(summary.SetupDurationNanos)),
			valueToCellData(durationToSecs(summary.TestDurationNanos)),
			valueToCellData(summary.SourceStats.ActualConnRate),

			// Resource usage
			valueToCellData(fgsSystemCpuPercent),
			valueToCellData(fgsUserCpuPercent),
			valueToCellData(summary.FgsCpuUsage.MaxRss),
			valueToCellData(sourceSystemCpuPercent),
			valueToCellData(sourceUserCpuPercent),
			valueToCellData(sinkSystemCpuPercent),
			valueToCellData(sinkUserCpuPercent),

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
			valueToCellData(getCpuName()),
		}
	}

}

func publishToSheets(sheetsService *sheets.Service, gitRev string, summary *bench.BenchSummary) {

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
		log.Fatalf("BatchUpdate failed: %s", err)
	}

	log.Printf("Append to %s / %d OK.\n", SHEET_DOC_ID, sheetId)
}

func getDerivedDataColumn(sheetsService *sheets.Service, column string) float64 {
	resp, err := sheetsService.Spreadsheets.Values.Get(SHEET_DOC_ID,
	                                      fmt.Sprintf("Derived Data!%s2:%s2", column, column)).Do()

	if err != nil {
		log.Fatalf("Failed to retrieve derived data value: %s", err)
	}

	fmt.Printf("Retrieved value: %v\n", resp.Values[0][0])

	f, err := strconv.ParseFloat(strings.TrimRight(fmt.Sprintf("%s", resp.Values[0][0]), "%"), 64)
	if err != nil {
		log.Fatalf("Failed to parse derived data value: %s", err)
	}
	return f
}


func getConnRatePercent(testA, testB string, summaries map[string]*bench.BenchSummary) float64 {
	return 100.0 * summaries[testA].SourceStats.ActualConnRate / summaries[testB].SourceStats.ActualConnRate
}

func getReqRatePercent(testA, testB string, summaries map[string]*bench.BenchSummary) float64 {
	return 100.0 * summaries[testA].SourceStats.ActualReqRate / summaries[testB].SourceStats.ActualReqRate
}

const prCommentTemplate = `Benchmark results ({{.GitRev}}):
- TLS connection rate with FGS (tls enabled) vs baseline: {{.TlsCrrPercent}}%
- TCP connection rate with FGS (tls enabled) vs baseline: {{.TcpCrrPercent}}% (vs master: {{.TcpCrrPercentDiff}}%)
- TCP request response rate with FGS (no tls) vs baseline: {{.TcpRrPercent}}%
- TCP request response rate with FGS (tls enabled) vs baseline: {{.TcpTlsRrPercent}}%
`

type PRCommentData struct {
	GitRev string
	TlsCrrPercent string
	TcpCrrPercent string
	TcpCrrPercentDiff string
	TcpRrPercent string
	TcpTlsRrPercent string
}

// Pretty-print the benchmark results for the PR comment that includes the difference to the latest
// nightly run.
func prettyPrintForPR(sheetsService *sheets.Service, gitRev string, summaries map[string]*bench.BenchSummary) {
	fmtFloat := func(f float64) string {
		return fmt.Sprintf("%.1f", f)
	}

	tcpCrrPercent := getConnRatePercent("BenchmarkFgsTls/tcp", "BenchmarkBaseline/tcp", summaries)
        tlsCrrPercent := getConnRatePercent("BenchmarkFgsTls/tls", "BenchmarkBaseline/tls", summaries)
	tcpRrPercent := getReqRatePercent("BenchmarkFgsTcpRequestResponse/tcp", "BenchmarkBaselineTcpRequestResponse", summaries)
        tcpTlsRrPercent := getReqRatePercent("BenchmarkFgsTls_TcpRequestResponse/tcp", "BenchmarkBaselineTcpRequestResponse", summaries)
	masterTcpCrrPercent := getDerivedDataColumn(sheetsService, "C")
	tcpCrrPercentDiff := fmtFloat(masterTcpCrrPercent - tcpCrrPercent)
	if masterTcpCrrPercent - tcpCrrPercent >= 0.0 {
		tcpCrrPercentDiff = "+" + tcpCrrPercentDiff
	}

	tmpl := strings.ReplaceAll(prCommentTemplate, "%", "%25")
	tmpl = strings.ReplaceAll(tmpl, "\n", "%0A")

	fmt.Print("::set-output name=body::")

	err := template.Must(template.New("comment").Parse(tmpl)).Execute(os.Stdout,
	          PRCommentData{
		          GitRev: gitRev,
		          TlsCrrPercent: fmtFloat(tlsCrrPercent),
		          TcpCrrPercent: fmtFloat(tcpCrrPercent),
		          TcpCrrPercentDiff: tcpCrrPercentDiff,
		          TcpRrPercent: fmtFloat(tcpRrPercent),
		          TcpTlsRrPercent: fmtFloat(tcpTlsRrPercent),
	          })

	if err != nil {
		log.Fatal(err)
	}
}
