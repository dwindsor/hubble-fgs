package testcontext

import (
	"context"
	"testing"
)

type TestContext struct {
	T             *testing.T
	Name          string
	ContainerId   string
	ContainerLogs []string
	Ctx           context.Context
}
