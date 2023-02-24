package testcontext

import (
	"context"
	"testing"
)

type TestContext struct {
	T           *testing.T
	Name        string
	ContainerId string
	Ctx         context.Context
}
