package ocsf

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/isovalent/ipa/ocsf/v1alpha"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
)

type OCSFClient struct {
	client v1alpha.EventServiceClient
	ctx    context.Context
	conn   *grpc.ClientConn
	stream grpc.ClientStreamingClient[v1alpha.ProcessEventsRequest, v1alpha.ProcessEventsResponse]
}

var (
	Retries    = 4
	ocsfClient *OCSFClient
)

// NewOCSFJSONClient return a connected client to a OCSF server
func NewOCSFJSONClient(ctx context.Context, serverAddr string) error {
	var err error

	ocsfClient = &OCSFClient{}

	backoff := time.Second
	attempts := 0
	for {
		ocsfClient.conn, err = grpc.NewClient(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			if attempts < Retries {
				// Exponential backoff
				attempts++
				logger.GetLogger().Error("Connection attempt failed, retrying...", "server-address", serverAddr, "attempts", attempts, logfields.Error, err)
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			logger.Fatal(logger.GetLogger(), "Failed to connect to OCSF server after multiple attempts",
				"server-address", serverAddr, "attempts", attempts, logfields.Error, err)
			return fmt.Errorf("server could not be reached")
		}
		break
	}
	ocsfClient.client = v1alpha.NewEventServiceClient(ocsfClient.conn)
	ocsfClient.ctx = ctx
	ocsfClient.stream, err = ocsfClient.client.ProcessEvents(ctx)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Client stream failed")
		return fmt.Errorf("client stream failed")
	}
	return nil
}

func SendOCSF(network *v1alpha.EndpointEvent_NetworkActivityDetail) error {
	var err error
	// If the stream failed return nil its not enabled and we have
	// original error in logs.
	if ocsfClient.stream == nil {
		ocsfClient.stream, err = ocsfClient.client.ProcessEvents(ocsfClient.ctx)
		if err != nil {
			logger.GetLogger().Debug("client stream never established retry")
			return nil
		}
	}
	json, err := protojson.Marshal(network.NetworkActivityDetail)
	if err != nil {
		return err
	}
	eventOcsf := &v1alpha.OcsfEvent{
		Json: string(json),
	}
	reqOcsf := &v1alpha.ProcessEventsRequest_OcsfEvent{
		OcsfEvent: eventOcsf,
	}
	req := &v1alpha.ProcessEventsRequest{
		Detail: reqOcsf,
	}
	err = ocsfClient.stream.Send(req)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Client stream send failed attempting reconnect")
		ocsfClient.stream, err = ocsfClient.client.ProcessEvents(ocsfClient.ctx)
	}
	return err
}
