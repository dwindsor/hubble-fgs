package grpc

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

type ClientMultiplexer struct {
	clients []tetragon.FineGuidanceSensorsClient
}

type connResult struct {
	*grpc.ClientConn
	Error error
}

type GetEventsResult struct {
	*tetragon.GetEventsResponse
	Error error
}

func (clients *ClientMultiplexer) GetEvents(ctx context.Context) chan GetEventsResult {
	c := make(chan GetEventsResult)

	for _, client := range clients.clients {
		stream, err := client.GetEvents(ctx, &tetragon.GetEventsRequest{})
		if err != nil {
			logger.GetLogger().WithError(err).Fatal("Failed to call GetEvents")
		}
		go func(stream tetragon.FineGuidanceSensors_GetEventsClient) {
			for {
				res, err := stream.Recv()
				c <- GetEventsResult{res, err}
			}
		}(stream)
	}

	return c
}

func Connect(ctx context.Context, connectTimeout time.Duration, addrs ...string) (*ClientMultiplexer, error) {
	// Set up connect timeout
	connCtx, connCancel := context.WithTimeout(ctx, connectTimeout)
	defer connCancel()

	// Connect to gRPC servers
	var wg sync.WaitGroup
	queue := make(chan connResult, len(addrs))
	wg.Add(len(addrs))
	for _, serverAddress := range addrs {
		logger.GetLogger().WithField("addr", serverAddress).Info("Connecting to gRPC server...")
		go func(serverAddress string) {
			defer wg.Done()
			conn, err := grpc.DialContext(connCtx, serverAddress, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock(), grpc.WithKeepaliveParams(keepalive.ClientParameters{
				Time:                20 * time.Second,
				Timeout:             connectTimeout,
				PermitWithoutStream: true,
			}))
			if err != nil {
				queue <- connResult{nil, fmt.Errorf("%s: %w", serverAddress, err)}
				return
			}
			queue <- connResult{conn, nil}
			logger.GetLogger().WithField("addr", serverAddress).Info("Connected to gRPC server")
		}(serverAddress)
	}

	// Close the channel when everything is connected
	go func() {
		wg.Wait()
		close(queue)
	}()

	// Pull connections out of the channel
	var conns []*grpc.ClientConn
	var connectionErrors []error
	for conn := range queue {
		if conn.Error != nil {
			connectionErrors = append(connectionErrors, conn.Error)
		} else {
			conns = append(conns, conn.ClientConn)
		}
	}

	// Close everything and abort if we failed to connect to some servers
	if len(connectionErrors) > 0 {
		for _, conn := range conns {
			conn.Close()
		}
		return nil, fmt.Errorf("Failed to connect to one or more gRPC servers: %v", connectionErrors)
	}

	// Splitting this up into a separate for-loop means the defer doesn't
	// depend on closing the channel (otherwise golint complains)
	var clients ClientMultiplexer
	for _, conn := range conns {
		client := tetragon.NewFineGuidanceSensorsClient(conn)
		clients.clients = append(clients.clients, client)
	}

	// Close the connections when the context is cancelled
	go func() {
		<-ctx.Done()
		for _, conn := range conns {
			conn.Close()
		}
	}()

	return &clients, nil
}
