package ocsf

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/ipa/ocsf/v1alpha"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
)

type OCSFClient struct {
	Client v1alpha.EventServiceClient
	Ctx    context.Context
	conn   *grpc.ClientConn
	cancel context.CancelFunc
}

var (
	Retries    = 4
	ocsfclient *OCSFClient
)

type daemonInfo struct {
	ServerAddr string `json:"server_address"`
}

var ocsfClient *OCSFClient

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
				logger.GetLogger().WithField("server-address", serverAddr).WithField("attempts", attempts).WithError(err).Error("Connection attempt failed, retrying...")
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			logger.GetLogger().WithField("server-address", serverAddr).WithField("attempts", attempts).WithError(err).Fatal("Failed to connect to server")
			return fmt.Errorf("server could not be reached")
		}
		break
	}

	ocsfClient.Client = v1alpha.NewEventServiceClient(ocsfClient.conn)
	ocsfClient.Ctx = ctx
	return nil
}

func SendOCSF(network *v1alpha.EndpointEvent_NetworkActivityDetail) error {
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
	stream, err := ocsfClient.Client.ProcessEvents(ocsfClient.Ctx)
	if err != nil {
		return err
	}
	return stream.Send(req)
}
