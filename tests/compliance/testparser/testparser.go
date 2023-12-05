package testparser

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type Test struct {
	Number      int
	Outcome     TestOutcome
	Description string
	Directive   string
	Diagnostics []string
}

func (test *Test) Summary() string {
	var optionalDescription string
	if test.Description != "" {
		optionalDescription = fmt.Sprintf(" \"%s\"", test.Description)
	}
	var optionalDirective string
	if test.Directive != "" {
		optionalDirective = " " + test.Directive
	}
	return fmt.Sprintf("Test %04d%s -> %s%s\n", test.Number, optionalDescription, test.Outcome, optionalDirective)
}

func (test *Test) Ok() bool {
	return test.Outcome != TestOutcomeFail && test.Outcome != TestOutcomeBailOut
}

type File struct {
	Name          string
	Expected      int
	Pass          int
	Fail          int
	Skip          int
	Todo          int
	Tests         []*Test
	BailOut       bool
	BailOutReason string
}

func (file *File) Summary() string {
	var s strings.Builder
	s.WriteString(fmt.Sprintf("--- %s ---\n", file.Name))
	for _, t := range file.Tests {
		s.WriteString(t.Summary())
	}
	if file.BailOut {
		s.WriteString(fmt.Sprintf("BAIL OUT: %s\n", file.BailOutReason))
	} else if file.Expected == 0 {
		s.WriteString("SKIP\n")
	} else if file.Ok() {
		s.WriteString("PASS\n")
	} else {
		s.WriteString("FAIL\n")
	}
	return s.String()
}

func (file *File) DumpFailures() string {
	var s strings.Builder
	s.WriteString(fmt.Sprintf("--- %s ---\n", file.Name))
	for _, t := range file.Tests {
		if t.Ok() {
			continue
		}
		s.WriteString(t.Summary())
		for i, line := range t.Diagnostics {
			if i != 0 {
				s.WriteRune('\n')
			}
			s.WriteString(fmt.Sprintf("\t%s", line))
		}

	}
	s.WriteRune('\n')
	return s.String()
}

func (file *File) Ok() bool {
	return file.Expected == file.Pass+file.Todo+file.Skip
}

func (file *File) NumTests() int {
	return file.Pass + file.Fail + file.Skip + file.Todo
}

type Results struct {
	Files []*File
}

func (res *Results) Summary() string {
	var expected int
	var pass int
	var fail int
	var skip int
	var todo int
	var s strings.Builder
	for _, f := range res.Files {
		s.WriteString(f.Summary())
		pass += f.Pass
		fail += f.Fail
		skip += f.Skip
		todo += f.Todo
		expected += f.Expected
	}
	summaryLine := fmt.Sprintf("    Expected=%d, Actual=%d (Pass=%d, Fail=%d, Skip=%d, Todo=%d)    ", expected, pass+fail+skip+todo, pass, fail, skip, todo)
	s.WriteString(strings.Repeat("=", len(summaryLine)))
	s.WriteRune('\n')
	s.WriteString(summaryLine)
	s.WriteRune('\n')
	s.WriteString(strings.Repeat("=", len(summaryLine)))
	s.WriteRune('\n')
	return s.String()
}

func (res *Results) DumpFailures() string {
	var s strings.Builder
	for _, f := range res.Files {
		if f.Ok() {
			continue
		}
		s.WriteString(f.DumpFailures())
	}
	s.WriteRune('\n')
	return s.String()
}

func (res *Results) Ok() bool {
	for _, f := range res.Files {
		if !f.Ok() {
			return false
		}
	}
	return true
}

type TestOutcome int

const (
	testOutcomeUnknown TestOutcome = iota
	TestOutcomePass
	TestOutcomeFail
	TestOutcomeTodo
	TestOutcomeSkip
	TestOutcomeBailOut
)

func (outcome TestOutcome) String() string {
	switch outcome {
	case TestOutcomePass:
		return "PASS"
	case TestOutcomeFail:
		return "FAIL"
	case TestOutcomeTodo:
		return "TODO"
	case TestOutcomeSkip:
		return "SKIP"
	case TestOutcomeBailOut:
		return "BAIL OUT"
	}
	panic(fmt.Sprintf("Unhandled test outcome: %d", outcome))
}

var fileLine = regexp.MustCompile(`^(.*)\s+\.+\s*$`)
var planLine = regexp.MustCompile(`^\d+\.\.(\d+)`)
var bailOutLine = regexp.MustCompile(`^(?i)bail out(?-i)!\s*(\S.*)?$`)
var testLine = regexp.MustCompile(`^(not )?ok\b(.*)`)
var optionalTestLine = regexp.MustCompile(`\s*(\d*)?(?:\s*-)?\s*([^#]*)(?:#\s*((\w*)\s*.*)\s*)?`)
var diagnosticLine = regexp.MustCompile(`^\s*#(.*)$`)

type TapParser struct{}

func (parser *TapParser) Parse(lines []string) *Results {
	results := &Results{}

	var file *File
	var test *Test

	for i := range lines {
		line := lines[i]
		match := fileLine.FindStringSubmatch(line)
		if match != nil {
			file = &File{
				Name: match[1],
			}
			results.Files = append(results.Files, file)
			test = nil

			continue
		}

		match = planLine.FindStringSubmatch(line)
		if match != nil {
			// This will always be an int
			expected, _ := strconv.Atoi(match[1])
			file.Expected = expected
			continue
		}

		match = testLine.FindStringSubmatch(line)
		if match != nil {
			if file.NumTests() == file.Expected {
				continue
			}
			test = &Test{}
			file.Tests = append(file.Tests, test)
			// Test result was "ok"
			if match[1] == "" {
				test.Outcome = TestOutcomePass
			} else {
				test.Outcome = TestOutcomeFail
			}

			// Parse the rest
			rest := match[2]
			match = optionalTestLine.FindStringSubmatch(rest)
			if match != nil {
				// Test number
				testNumString := match[1]
				// If it's not an integer, it's an empty string and we can just ignore it
				num, _ := strconv.Atoi(testNumString)
				test.Number = num

				// Description
				test.Description = strings.TrimSpace(match[2])

				// Directives
				directive := match[3]
				directiveKeyword := match[4]
				if strings.EqualFold(directiveKeyword, "skip") {
					test.Outcome = TestOutcomeSkip
				} else if strings.EqualFold(directiveKeyword, "todo") {
					test.Outcome = TestOutcomeTodo
				}
				test.Directive = directive
			}

			switch test.Outcome {
			case TestOutcomePass:
				file.Pass++
			case TestOutcomeFail:
				file.Fail++
			case TestOutcomeSkip:
				file.Skip++
			case TestOutcomeTodo:
				file.Todo++
			}
			continue
		}
		// The following only makes sense if we currently have an active test
		if test == nil {
			continue
		}
		match = diagnosticLine.FindStringSubmatch(line)
		if match != nil {
			test.Diagnostics = append(test.Diagnostics, strings.TrimSpace(match[1]))
			continue
		}
		match = bailOutLine.FindStringSubmatch(line)
		if match != nil {
			file.BailOut = true
			file.BailOutReason = match[1]
			continue
		}
	}

	return results
}

// func (test *Test) Summary() string {
// 	return fmt.Sprintf("%s - %s", test.Description, test.Outcome())
// }

// func (test *Test) Outcome() TestOutcome {
// 	switch {
// 	case test.Passed:
// 		return TestOutcomePass
// 	case test.Skipped:
// 		return TestOutcomeSkip
// 	case test.Todo:
// 		return TestOutcomeTodo
// 	case test.Failed:
// 		return TestOutcomeFail
// 	default:
// 		return testOutcomeUnknown
// 	}
// }

// // Results represents the overall result of a group of tests.
// type Results tap13.Results

// func (results *Results) Ok() bool {
// 	return (*tap13.Results)(results).IsPassing()
// }

// func (results *Results) Summary() string {
// 	return fmt.Sprintf("passed=%d failed=%d skipped=%d, todo=%d, bailout=%t, ok=%t", results.PassedTests, results.FailedTests, results.SkippedTests, results.TodoTests, results.BailOut, results.Ok())
// }

// func (results *Results) DumpFailures() string {
// 	builder := new(strings.Builder)
// 	if results.BailOut {
// 		builder.WriteString(fmt.Sprintf("Tests Bailed Out: %s\n", results.BailOutReason))
// 	}

// 	for _, test := range results.Tests {
// 		test := Test(test)
// 		if !test.Failed {
// 			continue
// 		}

// 		builder.WriteString(test.Summary())
// 		builder.WriteString("\n")
// 		for _, line := range test.Diagnostics {
// 			builder.WriteString(fmt.Sprintf("\n\t%s", line))
// 		}
// 		builder.WriteString("\n\n")
// 	}

// 	return builder.String()
// }

// // PerlTestHarnessParser implements ResultsParser for Perl's Test::Harness
// type PerlTestHarnessParser struct{}

// func (p *PerlTestHarnessParser) ResultsParse(testOutput []string) (*Results, error) {
// 	testOutput = append([]string{"TAP version 13"}, testOutput...)
// 	results := (*Results)(tap13.Parse(testOutput))
// 	if !results.FoundTapData {
// 		return results, fmt.Errorf("failed to find TAP data")
// 	}
// 	return results, nil
// }
