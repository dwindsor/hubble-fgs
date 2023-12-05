package testparser_test

import (
	_ "embed"
	"strings"
	"testing"

	"github.com/isovalent/hubble-fgs/tests/compliance/testparser"
	"github.com/stretchr/testify/assert"
)

func TestPerlTestHarnessParser_Simple(t *testing.T) {
	testOutput := []string{
		"TAP version 13",
		"./access.t ..",
		"1..14",
		"ok 1 - inet allow all",
		"ok 2 - inet allow unix",
		"ok 3 - inet deny all",
		"ok 4 - inet deny unix",
		"ok 5 - inet6 allow all",
		"ok 6 - inet6 allow unix",
		"ok 7 - inet6 deny all",
		"ok 8 - inet6 deny unix",
		"ok 9 - unix allow all",
		"ok 10 - unix allow unix",
		"ok 11 - unix deny all",
		"not ok 12 - unix deny unix",
		"",
		"#   Failed test 'unix deny unix'",
		"#   at ./access.t line 106.",
		"#                   'HTTP/1.1 403 Forbidden",
		"# Server: nginx/1.22.1",
		"# Date: Tue, 18 Apr 2023 14:11:34 GMT",
		"# Content-Type: text/html",
		"# Content-Length: 153",
		"# Connection: close",
		"#",
		"# <html>",
		"# <head><title>403 Forbidden</title></head>",
		"# <body>",
		"# <center><h1>403 Forbidden</h1></center>",
		"# <hr><center>nginx/1.22.1</center>",
		"# </body>",
		"# </html>",
		"# ",
		"ok 13 - no alerts",
		"ok 14 - no sanitizer errors",
		"# Looks like you failed 1 test of 14.",
		"Dubious, test returned 1 (wstat 256, 0x100)",
		"Failed 1/14 subtests",
		"",
		"Test Summary Report",
		"-------------------",
		"./access.t (Wstat: 256 (exited 1) Tests: 14 Failed: 1)",
		"  Failed test:  12",
		"  Non-zero exit status: 1",
		"Files=1, Tests=14,  0 wallclock secs ( 0.00 usr  0.00 sys +  0.03 cusr  0.00 csys =  0.03 CPU)",
		"Result: FAIL",
	}

	parser := testparser.TapParser{}
	results := parser.Parse(testOutput)

	assert.Equal(t, 1, len(results.Files), "number of files")
	assert.Equal(t, 13, results.Files[0].Pass, "passed tests")
	assert.Equal(t, 1, results.Files[0].Fail, "failed tests")
	assert.Equal(t, 0, results.Files[0].Skip, "skipped tests")
	assert.Equal(t, 14, results.Files[0].Expected, "expected tests")
	assert.Equal(t, 14, len(results.Files[0].Tests), "number of tests")

	assert.Equal(t, "unix deny unix", results.Files[0].Tests[11].Description, "description")
	assert.Equal(t, testparser.TestOutcomeFail, results.Files[0].Tests[11].Outcome, "test outcome")
	assert.Equal(t, 17, len(results.Files[0].Tests[11].Diagnostics), "diagnostic lines")
	assert.Equal(t, 12, results.Files[0].Tests[11].Number, "test number")
}

//go:embed testdata.txt
var TESTDATA string

func TestPerlTestHarnessParser_Full(t *testing.T) {
	testOutput := strings.Split(TESTDATA, "\n")

	parser := testparser.TapParser{}
	results := parser.Parse(testOutput)

	assert.Equal(t, 415, len(results.Files), "number of parsed files")
}
