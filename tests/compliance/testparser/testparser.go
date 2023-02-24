package testparser

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type TestOutcome string

const (
	testOutcomeUnknown TestOutcome = "UNKNOWN"
	TestOutcomePass    TestOutcome = "PASS"
	TestOutcomeFail    TestOutcome = "FAIL"
	TestOutcomeTodo    TestOutcome = "TODO"
	TestOutcomeSkip    TestOutcome = "SKIP"
)

// ResultsParser is a generic interface for parsing the results of a test suite into
// a summary.
type ResultsParser interface {
	ResultsParse(testOutput []string) (Results, error)
}

// Test represents a single test case.
type Test struct {
	// Name of the subtest
	Name string
	// Outcome of the test
	Outcome TestOutcome
	// Output of the test in case of failure
	Output []string
}

func (test *Test) Summary() string {
	return fmt.Sprintf("%s - %s", test.Name, test.Outcome)
}

// Results represents the overall result of a group of tests.
type Results struct {
	// Total number of passed tests
	Passed int
	// Total number of failed tests
	Failed int
	// Total number of skipped tests
	Skipped int
	// Total number of todo tests
	Todo int
	// Detailed information about individual tests
	Tests []Test
}

func (results *Results) Ok() bool {
	return results.Failed == 0
}

func (results *Results) Summary() string {
	return fmt.Sprintf("passed=%d failed=%d skipped=%d, todo=%d, ok=%t", results.Passed, results.Failed, results.Skipped, results.Todo, results.Ok())
}

func (results *Results) DumpFailures() string {
	builder := new(strings.Builder)

	for _, test := range results.Tests {
		if test.Outcome != TestOutcomeFail {
			continue
		}

		builder.WriteString(test.Summary())
		builder.WriteString("\n")
		for _, line := range test.Output {
			builder.WriteString(fmt.Sprintf("\n\t%s", line))
		}
		builder.WriteString("\n\n")
	}

	return builder.String()
}

// PerlTestHarnessParser implements ResultsParser for Perl's Test::Harness
type PerlTestHarnessParser struct{}

func (p *PerlTestHarnessParser) ResultsParse(testOutput []string) (*Results, error) {
	var results = new(Results)
	var currentTest *Test

	testRe := regexp.MustCompile(`^(ok|not ok)\s+(\d+)(?:\s+-\s+([^#]+))?(?:\s+#\s+((?i)SKIP|TODO)\s*(.*))?$`)
	diagnosticRe := regexp.MustCompile(`^#\s?(.*)$`)
	summaryRe := regexp.MustCompile(`^Files=(\d+), Tests=(\d+),`)

	for _, line := range testOutput {
		if testMatch := testRe.FindStringSubmatch(line); testMatch != nil {
			// Append the previously parsed test
			if currentTest != nil {
				results.Tests = append(results.Tests, *currentTest)
			}

			passed := testMatch[1] == "ok"
			failed := testMatch[1] == "not ok"
			skipped := strings.ToLower(testMatch[4]) == "skip"
			todo := strings.ToLower(testMatch[4]) == "todo"
			name := strings.TrimSpace(testMatch[3])

			var outcome TestOutcome
			if skipped {
				outcome = TestOutcomeSkip
			} else if todo {
				outcome = TestOutcomeTodo
			} else if passed {
				outcome = TestOutcomePass
			} else if failed {
				outcome = TestOutcomeFail
			}
			if outcome == testOutcomeUnknown {
				return nil, fmt.Errorf("parsing error: unknown test outcome")
			}

			currentTest = &Test{
				Name:    name,
				Outcome: outcome,
			}
		} else if diagnosticMatch := diagnosticRe.FindStringSubmatch(line); diagnosticMatch != nil {
			if currentTest != nil && (currentTest.Outcome == TestOutcomeFail || currentTest.Outcome == TestOutcomeTodo) {
				currentTest.Output = append(currentTest.Output, diagnosticMatch[1])
			}
		} else if summaryMatch := summaryRe.FindStringSubmatch(line); summaryMatch != nil {
			// Append the final test
			if currentTest != nil {
				results.Tests = append(results.Tests, *currentTest)
			}

			totalTests, err := strconv.Atoi(summaryMatch[2])
			if err != nil {
				return nil, fmt.Errorf("bad totalTests: %s", summaryMatch[2])
			}

			for _, test := range results.Tests {
				switch test.Outcome {
				case TestOutcomePass:
					results.Passed++
				case TestOutcomeFail:
					results.Failed++
				case TestOutcomeSkip:
					results.Skipped++
				case TestOutcomeTodo:
					results.Todo++
				}
			}

			if totalTests != results.Passed+results.Failed+results.Skipped+results.Todo {
				return nil, fmt.Errorf("parsed tests count does not match summary: %d != %d", totalTests, results.Passed+results.Failed+results.Skipped+results.Todo)
			}
		}
	}

	return results, nil
}
