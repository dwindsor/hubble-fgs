package compliance

import (
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/isovalent/hubble-fgs/tests/compliance/testcontext"
	"github.com/isovalent/hubble-fgs/tests/compliance/testparser"

	"github.com/isovalent/hubble-fgs/tests/compliance/util"
)

type Stepper interface {
	Step(ctx *testcontext.TestContext) TestStepError
}

type RunCommandStep struct {
	// Command to run.
	Cmd []string
	// Environment variables e.g. FOO=bar
	Env []string
	// Event checker to run if any.
	Checker eventchecker.MultiEventChecker
}

func (step *RunCommandStep) Step(ctx *testcontext.TestContext) TestStepError {
	// TODO capture output and add it to custom error type
	if _, err := util.RunCommandInContainerWithEnvironment(ctx, step.Env, step.Cmd...); err != nil {
		return err
	}

	// TODO: run event checker here

	return nil
}

type ProveStep struct {
	// One or more glob filters for tests to run.
	Filters []string
	TestDir string
	Checker eventchecker.MultiEventChecker
}

func (step *ProveStep) Step(ctx *testcontext.TestContext) TestStepError {
	args := []string{"prove", "-v", "--nocolor", "--normalize"}
	if len(step.Filters) > 0 {
		args = append(args, step.Filters...)
	} else {
		args = append(args, step.TestDir)
	}

	out, err := util.RunCommandInContainerWithEnvironment(ctx, []string{}, args...)
	parser := testparser.PerlTestHarnessParser{}
	results, _ := parser.ResultsParse(out)
	if results != nil {
		ctx.T.Log("Test Results Summary:", results.Summary())
		if !results.Ok() {
			ctx.T.Logf("Failed Tests Summary:\n%s", results.DumpFailures())
		}
	}
	if err != nil {
		return err
	}

	// TODO: run event checker here

	return nil
}
