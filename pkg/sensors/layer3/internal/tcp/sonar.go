//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sigv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	colmpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	cpb "go.opentelemetry.io/proto/otlp/common/v1"
	mpb "go.opentelemetry.io/proto/otlp/metrics/v1"
	rpb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/timer"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/grpc/sockinfo"
	"github.com/isovalent/hubble-fgs/pkg/option"
	reader "github.com/isovalent/hubble-fgs/pkg/reader/network"
)

const (
	sonarService = "networksonar"
)

var (
	sonarInterval = 30 * time.Second
	sonarJitter   = 5 * time.Second

	scopeMetricsList []*mpb.ScopeMetrics

	// collection timestamps
	// TODO: Track them per scope (socket) instead of globally.
	lastCollectTs uint64
	currentTs     uint64
)

func getDataHistogram(value float64) *mpb.Metric_Histogram {
	hdp := []*mpb.HistogramDataPoint{
		{
			StartTimeUnixNano: lastCollectTs,
			TimeUnixNano:      currentTs,
			Count:             1,
			Sum:               &value,
		},
	}
	hist := &mpb.Histogram{
		AggregationTemporality: mpb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
		DataPoints:             hdp,
	}
	return &mpb.Metric_Histogram{
		Histogram: hist,
	}
}

func roundTripsTotal(rtt *tetragon.Histogram) float64 {
	var total float64
	if rtt != nil && rtt.Buckets != nil {
		for _, bucket := range rtt.Buckets {
			total += float64(bucket.Count)
		}
	}
	return total
}

func addTCPMetricsForSocket(k *networkapi.TcpKey, v *networkapi.TcpValue, tuple *networkapi.MsgIPTuple, stats *networkapi.MsgSocketStats) {
	event := socketStatsToIPWithStatsEventUnix(k, v, tuple, stats)

	// see also pkg/grpc/layer3/layer3.go:CreateProcessSockStats
	fgsTuple := sockinfo.GetTuple(&event.Msg.Tuple, event.Msg.SockCookie, event.Msg.Common.Op)
	fgsSocketStats := reader.GetSocketStats(&event.Msg.SocketStats)

	attributes := []*cpb.KeyValue{
		{
			Key: "local_address", Value: &cpb.AnyValue{
				Value: &cpb.AnyValue_StringValue{StringValue: fgsTuple.SourceIp},
			},
		},
		{
			Key: "remote_address", Value: &cpb.AnyValue{
				Value: &cpb.AnyValue_StringValue{StringValue: fgsTuple.DestinationIp},
			},
		},
		{
			Key: "protocol", Value: &cpb.AnyValue{
				Value: &cpb.AnyValue_StringValue{StringValue: fgsTuple.Protocol.String()},
			},
		},
	}
	if fgsTuple.DestinationPort != nil {
		attributes = append(attributes, &cpb.KeyValue{
			Key: "remote_port", Value: &cpb.AnyValue{
				Value: &cpb.AnyValue_IntValue{IntValue: int64(fgsTuple.DestinationPort.Value)},
			},
		})
	}

	scopeMetrics := &mpb.ScopeMetrics{
		Scope: &cpb.InstrumentationScope{
			Name:       "network_stat",
			Attributes: attributes,
		},
		Metrics: []*mpb.Metric{
			// {
			// 	Name:        "sockets_total",
			// 	Description: "The number of currently active connections",
			// 	Unit:        "1",
			// 	Data:        nil,
			// },
			// {
			// 	Name:        "sockets_closed",
			// 	Description: "The number of connections that have closed",
			// 	Unit:        "1",
			// 	Data:        nil,
			// },
			// {
			// 	Name:        "sockets_ended_early",
			// 	Description: "The number of connections that ended prematurely",
			// 	Unit:        "1",
			// 	Data:        nil,
			// },
			{
				Name:        "bytes_received",
				Description: "Bytes received",
				Unit:        "1",
				Data:        getDataHistogram(float64(fgsSocketStats.BytesReceived)),
			},
			// Tetragon collects only bytes_sent, this should be bytes_acked.
			// {
			// 	Name:        "bytes_delivered",
			// 	Description: "Bytes acknowledged by the remote endpoint",
			// 	Unit:        "1",
			// 	Data:        nil,
			// },
			// {
			//  Name:        "connect_ms_max",
			//  Description: "The max time to complete an outbound connection",
			//  Unit:        "1",
			//  Data:        nil,
			// },
			{
				Name:        "rtt_count",
				Description: "The number of round trips",
				Unit:        "1",
				Data:        getDataHistogram(roundTripsTotal(fgsSocketStats.Rtt)),
			},
			// {
			// 	Name:        "rtt_min_us",
			// 	Description: "The lowest round-trip time",
			// 	Unit:        "1",
			// 	Data:        nil,
			// },
			// {
			// 	Name:        "rtt_max_us",
			// 	Description: "The highest round-trip time",
			// 	Unit:        "1",
			// 	Data:        nil,
			// },
			{
				Name:        "rtt_smoothed_us",
				Description: "The average round-trip time",
				Unit:        "1",
				Data:        getDataHistogram(float64(fgsSocketStats.Srtt)),
			},
			{
				Name:        "retrans_total",
				Description: "The number of retransmissions",
				Unit:        "1",
				Data:        getDataHistogram(float64(fgsSocketStats.RetransmitsSegs)),
			},
			// {
			// 	Name:        "retrans_timeouts",
			// 	Description: "The number of retransmission timeouts",
			// 	Unit:        "1",
			// 	Data:        nil,
			// },
		},
	}

	// add to the metrics list
	scopeMetricsList = append(scopeMetricsList, scopeMetrics)
}

func createExportRequest() *colmpb.ExportMetricsServiceRequest {
	exportRequest := &colmpb.ExportMetricsServiceRequest{
		ResourceMetrics: []*mpb.ResourceMetrics{
			{
				ScopeMetrics: []*mpb.ScopeMetrics{
					// process-wide counters that have been observed since the last report
					// time (sockets established and closed, number of events processed, etc.).
					// {
					// 	Scope: &cpb.InstrumentationScope{
					// 		Name: "counters",
					// 	},
					// 	Metrics: []*mpb.Metric{
					// 		{
					// 			Name: "active_connect_events",
					// 			Unit: "1",
					// 			Data: nil,
					// 		},
					// 		{
					// 			Name: "active_established_events",
					// 			Unit: "1",
					// 			Data: nil,
					// 		},
					// 		{
					// 			Name: "passive_established_events",
					// 			Unit: "1",
					// 			Data: nil,
					// 		},
					// 		{
					// 			Name: "state_change_events",
					// 			Unit: "1",
					// 			Data: nil,
					// 		},
					// 		{
					// 			Name: "rtt_events",
					// 			Unit: "1",
					// 			Data: nil,
					// 		},
					// 		{
					// 			Name: "retrans_events",
					// 			Unit: "1",
					// 			Data: nil,
					// 		},
					// 		{
					// 			Name: "rto_events",
					// 			Unit: "1",
					// 			Data: nil,
					// 		},
					// 		{
					// 			Name: "other_events",
					// 			Unit: "1",
					// 			Data: nil,
					// 		},
					// 		{
					// 			Name: "socket_events",
					// 			Unit: "1",
					// 			Data: nil,
					// 		},
					// 		{
					// 			Name: "sockets_invalid",
					// 			Unit: "1",
					// 			Data: nil,
					// 		},
					// 		{
					// 			Name: "sockets_stale",
					// 			Unit: "1",
					// 			Data: nil,
					// 		},
					// 		{
					// 			Name: "socket_eviction_errors",
					// 			Unit: "1",
					// 			Data: nil,
					// 		},
					// 	},
					// },
					// information on the process’ resource consumption (CPU, memory
					// and socks tracked).
					// {
					// 	Scope: &cpb.InstrumentationScope{
					// 		Name: "process_stat",
					// 	},
					// 	Metrics: []*mpb.Metric{
					// 		{
					// 			Name: "cpu_active",
					// 			Unit: "1",
					// 			Data: nil,
					// 		},
					// 		{
					// 			Name: "cpu_overall",
					// 			Unit: "1",
					// 			Data: nil,
					// 		},
					// 		{
					// 			Name: "mem_used_kb",
					// 			Unit: "1",
					// 			Data: nil,
					// 		},
					// 		{
					// 			Name: "mem_used_ratio",
					// 			Unit: "1",
					// 			Data: nil,
					// 		},
					// 		{
					// 			Name: "sockets_tracked",
					// 			Unit: "1",
					// 			Data: nil,
					// 		},
					// 	},
					// },
				},
			},
		},
	}

	// assume the metrics list is correctly populated at this point
	exportRequest.ResourceMetrics[0].ScopeMetrics = append(exportRequest.ResourceMetrics[0].ScopeMetrics, scopeMetricsList...)

	return exportRequest
}

func getInstanceID() (string, error) {
	content, err := os.ReadFile("/var/lib/cloud/data/instance-id")
	if err != nil {
		return "", fmt.Errorf("failed to read instance-id file: %w", err)
	}

	return strings.TrimSuffix(string(content), "\n"), nil
}

func createResource(_ context.Context, _ aws.Config) *rpb.Resource {
	resource := &rpb.Resource{
		Attributes: []*cpb.KeyValue{
			// {
			// 	Key: "machine_id", Value: &cpb.AnyValue{
			// 		Value: &cpb.AnyValue_StringValue{StringValue: "TODO"},
			// 	},
			// },
			// {
			// 	Key: "agent_version", Value: &cpb.AnyValue{
			// 		Value: &cpb.AnyValue_StringValue{StringValue: "TODO"},
			// 	},
			// },
			// {
			// 	Key: "service_version", Value: &cpb.AnyValue{
			// 		Value: &cpb.AnyValue_StringValue{StringValue: "TODO"},
			// 	},
			// },
		},
	}

	// add instance ID
	instanceID, err := getInstanceID()
	if err != nil || instanceID == "" {
		logger.GetLogger().WithError(err).Warn("failed to get EC2 instance ID")
		return resource
	}
	resource.Attributes = append(resource.Attributes, &cpb.KeyValue{
		Key: "instance_id", Value: &cpb.AnyValue{
			Value: &cpb.AnyValue_StringValue{StringValue: instanceID},
		},
	})

	// add subnet and VPC IDs
	// ec2Client := ec2.NewFromConfig(cfg)
	// ec2Input := &ec2.DescribeInstancesInput{
	// 	InstanceIds: []string{instanceID},
	// }
	// ec2Instances, err := ec2Client.DescribeInstances(ctx, ec2Input)
	// if err != nil {
	// 	logger.GetLogger().WithError(err).Warn("failed to describe EC2 instances")
	// 	return resource
	// }
	// var subnetID, vpcID string
	// we expect exactly one instance in the response
	// if ec2Instances != nil && len(ec2Instances.Reservations) > 0 && len(ec2Instances.Reservations[0].Instances) > 0 {
	// 	instance := ec2Instances.Reservations[0].Instances[0]
	// 	subnetID = aws.ToString(instance.SubnetId)
	// 	vpcID = aws.ToString(instance.VpcId)
	// }
	// if subnetID != "" {
	// 	resource.Attributes = append(resource.Attributes, &cpb.KeyValue{
	// 		Key: "subnet_id", Value: &cpb.AnyValue{
	// 			Value: &cpb.AnyValue_StringValue{StringValue: subnetID},
	// 		},
	// 	})
	// }
	// if vpcID != "" {
	// 	resource.Attributes = append(resource.Attributes, &cpb.KeyValue{
	// 		Key: "vpc_id", Value: &cpb.AnyValue{
	// 			Value: &cpb.AnyValue_StringValue{StringValue: vpcID},
	// 		},
	// 	})
	// }

	return resource
}

func postMetrics(ctx context.Context) error {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// create ExportMetricsServiceRequest
	exportRequest := createExportRequest()
	resource := createResource(ctx, cfg)
	// assume there is exactly one ResourceMetrics in the request
	exportRequest.ResourceMetrics[0].Resource = resource

	// create request
	data, err := proto.Marshal(exportRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal ExportMetricsServiceRequest: %w", err)
	}
	sonarEndpoint := fmt.Sprintf("https://ingestion.%s.dataplane.sonar.networking.aws.dev/publish", option.Config.AWSSonarRegion)
	req, err := http.NewRequest("POST", sonarEndpoint, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create a request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-protobuf")

	// sign request
	creds, err := aws.CredentialsProvider(cfg.Credentials).Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve credentials: %w", err)
	}
	hash := sha256.Sum256(data)
	hexHash := hex.EncodeToString(hash[:])
	signer := sigv4.NewSigner()
	if err = signer.SignHTTP(ctx, creds, req, hexHash, sonarService, option.Config.AWSSonarRegion, time.Now()); err != nil {
		return fmt.Errorf("failed to sign a request: %w", err)
	}

	// send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make a request: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

func InitSonar(ctx context.Context) {
	// defined here to capture ctx
	sonarCollect := func() {
		sleep := time.Duration(rand.Int63n(2*sonarJitter.Milliseconds())) * time.Millisecond
		time.Sleep(sleep)

		// reset the metrics list
		scopeMetricsList = []*mpb.ScopeMetrics{}
		// set collection timestamp
		currentTs = uint64(time.Now().UnixNano())

		getRunTcpGC(addTCPMetricsForSocket)()

		err := postMetrics(ctx)
		if err != nil {
			logger.GetLogger().WithError(err).Error("Failed to post metrics to Sonar")
		}

		// update last collection timestamp
		lastCollectTs = currentTs
	}

	sonarTimer := timer.NewPeriodicTimer("Sonar Timer", sonarCollect, false)
	logger.GetLogger().Info("Starting posting metrics to Sonar")
	sonarTimer.Start(sonarInterval - sonarJitter)
}
