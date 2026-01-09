// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

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

type TapOutputStep struct{}

func (step *TapOutputStep) Step(ctx *testcontext.TestContext) TestStepError {
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

type WaitContainerStep struct{}

func (step *WaitContainerStep) Step(ctx *testcontext.TestContext) TestStepError {
	// Wait for container to exit
	res, err := util.WaitForContainer(ctx)
	if err != nil {
		return fmt.Errorf("error waiting for container: %w", err)
	}
	if res.Error != nil {
		return fmt.Errorf("container error: %s", res.Error.Message)
	}
	if res.StatusCode != 0 {
		return fmt.Errorf("non-zero exit code from container: %d", res.StatusCode)
	}

	return nil
}
