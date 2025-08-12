package exec

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/cilium/tetragon/cmd/tetra/common"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

type ApplicationModelClient struct {
	Client appModelV1.ApplicationModelServiceClient
	// Ctx is a combination of the signal context and the timeout context
	Ctx context.Context
	// SignalCtx is only the signal context, you might want to use that context
	// when the command should never timeout (like a stream command)
	SignalCtx context.Context
	conn      *grpc.ClientConn
	// The signal context is the parent of the timeout context, so cancelling
	// signal will cancel its child, timeout
	signalCancel  context.CancelFunc
	timeoutCancel context.CancelFunc
}

// NewApplicationModelClient return a connected client to a tetragon server, caller
// must call Close() on the client. On failure to connect, this function calls
// Fatal() thus stopping execution.
func NewApplicationModelClient(ctx context.Context) (*ApplicationModelClient, error) {
	c := &ApplicationModelClient{}
	c.SignalCtx, c.signalCancel = signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	c.Ctx, c.timeoutCancel = context.WithTimeout(c.SignalCtx, common.Timeout)

	var err error
	address := common.ResolveServerAddress()
	c.conn, err = grpc.NewClient(address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultServiceConfig(common.RetryPolicy(common.Retries)),
		grpc.WithMaxCallAttempts(common.Retries+1), // maxAttempt includes the first call
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client with address %s: %w", address, err)
	}

	c.Client = appModelV1.NewApplicationModelServiceClient(c.conn)
	return c, nil
}

func (c ApplicationModelClient) Close() {
	c.conn.Close()
	c.signalCancel()
	c.timeoutCancel()
}

type ConnectedModelClient struct {
	Client tetragon.ProcessModelServiceClient
	// Ctx is a combination of the signal context and the timeout context
	Ctx context.Context
	// SignalCtx is only the signal context, you might want to use that context
	// when the command should never timeout (like a stream command)
	SignalCtx context.Context
	conn      *grpc.ClientConn
	// The signal context is the parent of the timeout context, so cancelling
	// signal will cancel its child, timeout
	signalCancel  context.CancelFunc
	timeoutCancel context.CancelFunc
}

// NewConnectedClient return a connected client to a tetragon server, caller
// must call Close() on the client. On failure to connect, this function calls
// Fatal() thus stopping execution.
func NewConnectedModelClient(ctx context.Context) (*ConnectedModelClient, error) {
	c := &ConnectedModelClient{}
	c.SignalCtx, c.signalCancel = signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	c.Ctx, c.timeoutCancel = context.WithTimeout(c.SignalCtx, common.Timeout)

	var err error
	address := common.ResolveServerAddress()
	c.conn, err = grpc.NewClient(address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultServiceConfig(common.RetryPolicy(common.Retries)),
		grpc.WithMaxCallAttempts(common.Retries+1), // maxAttempt includes the first call
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client with address %s: %w", address, err)
	}

	c.Client = tetragon.NewProcessModelServiceClient(c.conn)
	return c, nil
}

// Close cleanup resources, it closes the connection and cancel the context
func (c ConnectedModelClient) Close() {
	c.conn.Close()
	c.signalCancel()
	c.timeoutCancel()
}
