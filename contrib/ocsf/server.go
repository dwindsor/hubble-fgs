package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/isovalent/ipa/ocsf/v1alpha"
	"google.golang.org/grpc"
)

var (
	StreamOCSFEvent = make(chan *v1alpha.EndpointEvent)
)

func main() {
	port := 54322
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	fmt.Printf("listen...")
	grpcServer := grpc.NewServer()
	v1alpha.RegisterEventServiceServer(grpcServer, newServer())
	grpcServer.Serve(lis)
}

type Server struct {
	v1alpha.UnimplementedEventServiceServer
}

func (s *Server) ProcessEvents(stream grpc.ClientStreamingServer[v1alpha.ProcessEventsRequest, v1alpha.ProcessEventsResponse]) error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-signals
		cancel()
	}()

	for {
		select {
		case <-ctx.Done():
			return stream.SendAndClose(&v1alpha.ProcessEventsResponse{
				Message: "done",
			})
		default:
			req, err := stream.Recv()
			if err != nil {
				return stream.SendAndClose(&v1alpha.ProcessEventsResponse{
					Message: "done",
				})
			}
			fmt.Println(req)
		}
	}
}

func newServer() *Server {
	return &Server{}
}
