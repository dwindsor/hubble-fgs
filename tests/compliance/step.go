package compliance

import (
	"fmt"

	"github.com/isovalent/hubble-fgs/tests/compliance/testcontext"
	"github.com/isovalent/hubble-fgs/tests/compliance/testparser"
	"github.com/isovalent/hubble-fgs/tests/compliance/util"
)

type Stepper interface {
	Step(ctx *testcontext.TestContext) TestStepError
}

type ProveStep struct{}

func (step *ProveStep) Step(ctx *testcontext.TestContext) TestStepError {
	// Wait for container to exit
	util.WaitForContainer(ctx)

	parser := testparser.TapParser{}
	results := parser.Parse(ctx.ContainerLogs)
	if results != nil {
		ctx.T.Log("Test Results Summary:", results.Summary())
		if !results.Ok() {
			ctx.T.Logf("Failed Tests Summary:\n%s", results.DumpFailures())
			return fmt.Errorf("prove step failure: not all tests ok")
		}
	}

	return nil
}
