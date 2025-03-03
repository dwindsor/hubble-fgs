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
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sigv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	lru "github.com/hashicorp/golang-lru/v2"
	colmpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	cpb "go.opentelemetry.io/proto/otlp/common/v1"
	mpb "go.opentelemetry.io/proto/otlp/metrics/v1"
	rpb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/version"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/grpc/sockinfo"
	"github.com/isovalent/hubble-fgs/pkg/option"
	reader "github.com/isovalent/hubble-fgs/pkg/reader/network"
)

const (
	sonarService = "networkflowmonitor"
)

var (
	sonarInterval = 30 * time.Second
	sonarJitter   = 5 * time.Second
	sonarStats    statsManager

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

func addTCPMetricsForSocket(k *networkapi.TcpKey, v *networkapi.TcpValue, stats *networkapi.MsgSocketStats) {
	event := socketStatsToIPWithStatsEventUnix(k, v, stats)

	// see also pkg/grpc/layer3/layer3.go:CreateProcessSockStats
	var fgsProcess *tetragon.Process
	p, _ := process.GetParentProcessInternal(event.Msg.ProcessKey.Pid, event.Msg.ProcessKey.Ktime)
	if p == nil {
		fgsProcess = &tetragon.Process{
			Pid:       &wrapperspb.UInt32Value{Value: event.Msg.ProcessKey.Pid},
			StartTime: ktime.ToProto(event.Msg.ProcessKey.Ktime),
		}
	} else {
		fgsProcess = p.UnsafeGetProcess()
	}
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
	if fgsTuple.SourcePort != nil {
		attributes = append(attributes, &cpb.KeyValue{
			Key: "local_port", Value: &cpb.AnyValue{
				Value: &cpb.AnyValue_IntValue{IntValue: int64(fgsTuple.SourcePort.Value)},
			},
		})
	}
	if fgsTuple.DestinationPort != nil {
		attributes = append(attributes, &cpb.KeyValue{
			Key: "remote_port", Value: &cpb.AnyValue{
				Value: &cpb.AnyValue_IntValue{IntValue: int64(fgsTuple.DestinationPort.Value)},
			},
		})
	}
	if fgsProcess.Pod != nil {
		attributes = append(attributes, &cpb.KeyValue{
			Key: "local_pod_name", Value: &cpb.AnyValue{
				Value: &cpb.AnyValue_StringValue{StringValue: fgsProcess.Pod.Name},
			},
		}, &cpb.KeyValue{
			// Send workload name as service. It might be not what Sonar
			// expects, but it might as well be close enough.
			Key: "local_pod_service", Value: &cpb.AnyValue{
				Value: &cpb.AnyValue_StringValue{StringValue: fgsProcess.Pod.Workload},
			},
		}, &cpb.KeyValue{
			Key: "local_pod_namespace", Value: &cpb.AnyValue{
				Value: &cpb.AnyValue_StringValue{StringValue: fgsProcess.Pod.Namespace},
			},
		})
	}
	if fgsTuple.DestinationPod != nil {
		attributes = append(attributes, &cpb.KeyValue{
			Key: "remote_pod_name", Value: &cpb.AnyValue{
				Value: &cpb.AnyValue_StringValue{StringValue: fgsTuple.DestinationPod.Name},
			},
		}, &cpb.KeyValue{
			// Send workload name as service. It might be not what Sonar
			// expects, but it might as well be close enough.
			Key: "remote_pod_service", Value: &cpb.AnyValue{
				Value: &cpb.AnyValue_StringValue{StringValue: fgsTuple.DestinationPod.Workload},
			},
		}, &cpb.KeyValue{
			Key: "remote_pod_namespace", Value: &cpb.AnyValue{
				Value: &cpb.AnyValue_StringValue{StringValue: fgsTuple.DestinationPod.Namespace},
			},
		})
	}

	scopeMetrics := &mpb.ScopeMetrics{
		Scope: &cpb.InstrumentationScope{
			Name:       "network_stat",
			Attributes: attributes,
		},
		Metrics: []*mpb.Metric{
			// sockets_total, sockets_closed and sockets_ended_early were removed in report version
			// 1.1 in favor of per-state socket counts.
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

			// Per-state socket counts were introduced in report version 1.1.
			// {
			// 	Name:        "sockets_connecting",
			// 	Description: "The number of sockets currently connecting",
			// 	Unit:        "1",
			// 	Data:        nil,
			// },
			// {
			// 	Name:        "sockets_established",
			// 	Description: "The number of sockets currently established",
			// 	Unit:        "1",
			// 	Data:        nil,
			// },
			// {
			// 	Name:        "sockets_closing",
			// 	Description: "The number of sockets currently closed but still in memory",
			// 	Unit:        "1",
			// 	Data:        nil,
			// },
			// {
			// 	Name:        "sockets_closed",
			// 	Description: "The number of sockets currently closed",
			// 	Unit:        "1",
			// 	Data:        nil,
			// },
			// {
			// 	Name:        "sockets_completed",
			// 	Description: "The number of sockets completed during the prior window",
			// 	Unit:        "1",
			// 	Data:        nil,
			// },
			// {
			// 	Name:        "severed_connect",
			// 	Description: "The number of sockets severed while connecting",
			// 	Unit:        "1",
			// 	Data:        nil,
			// },
			// {
			// 	Name:        "severed_establish",
			// 	Description: "The number of sockets severed while established",
			// 	Unit:        "1",
			// 	Data:        nil,
			// },

			{
				Name:        "bytes_received",
				Description: "Bytes received",
				Unit:        "1",
				Data:        getDataHistogram(float64(fgsSocketStats.BytesReceived)),
			},
			// Sonar expects bytes_acked, but Tetragon collects only bytes_sent.
			// To avoid collecting two similar metrics let's just hope they're close enough.
			{
				Name:        "bytes_delivered",
				Description: "Bytes acknowledged by the remote endpoint",
				Unit:        "1",
				Data:        getDataHistogram(float64(fgsSocketStats.BytesSent)),
			},
			// {
			//  Name:        "connect_max_us",
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

			// retrans_total and retrans_timeouts were removed in report version 1.1 in favor of
			// per-flag retransmission metrics.
			{
				Name:        "retrans_total",
				Description: "The number of retransmissions sent and received",
				Unit:        "1",
				Data:        getDataHistogram(float64(fgsSocketStats.RetransmitsSegs)),
			},
			// {
			// 	Name:        "retrans_timeouts",
			// 	Description: "The number of retransmission timeouts",
			// 	Unit:        "1",
			// 	Data:        nil,
			// },

			// Per-flag retransmission metrics were introduced in report version 1.1.
			// {
			// 	Name:        "retrans_syn",
			// 	Description: "The number of retransmissions while connecting",
			// 	Unit:        "1",
			// 	Data:        nil,
			// },
			// {
			// 	Name:        "retrans_est",
			// 	Description: "The number of retransmissions while established",
			// 	Unit:        "1",
			// 	Data:        nil,
			// },
			// {
			// 	Name:        "retrans_close",
			// 	Description: "The number of retransmissions while closing",
			// 	Unit:        "1",
			// 	Data:        nil,
			// },
			// {
			// 	Name:        "rtos_syn",
			// 	Description: "The number of RTOs while connecting",
			// 	Unit:        "1",
			// 	Data:        nil,
			// },
			// {
			// 	Name:        "rtos_est",
			// 	Description: "The number of RTOs while connecting",
			// 	Unit:        "1",
			// 	Data:        nil,
			// },
			// {
			// 	Name:        "rtos_close",
			// 	Description: "The number of RTOs while closing",
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
					// 			Name: "sockets_added",
					// 			Unit: "1",
					// 			Data: nil,
					// 		},
					// 		{
					// 			Name: "sockets_aggregated",
					// 			Unit: "1",
					// 			Data: nil,
					// 		},
					// 		{
					// 			Name: "sockets_stale",
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
					// 			Name: "cpu_util",
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
					// 		{
					// 			Name: "publish_report_failed",
					// 			Unit: "1",
					// 			Data: nil,
					// 		},
					// 		{
					// 			Name: "restarts",
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
			{
				Key: "service.name", Value: &cpb.AnyValue{
					Value: &cpb.AnyValue_StringValue{StringValue: "Tetragon"},
				},
			},
			{
				Key: "service.version", Value: &cpb.AnyValue{
					Value: &cpb.AnyValue_StringValue{StringValue: version.Version},
				},
			},
			// {
			// 	Key: "agent.build_ts", Value: &cpb.AnyValue{
			// 		Value: &cpb.AnyValue_StringValue{StringValue: "TODO"},
			// 	},
			// },
			{
				Key: "report.version", Value: &cpb.AnyValue{
					Value: &cpb.AnyValue_StringValue{StringValue: "1.0"},
				},
			},
			{
				Key: "k8s_node_name", Value: &cpb.AnyValue{
					Value: &cpb.AnyValue_StringValue{StringValue: node.GetNodeNameForExport()},
				},
			},
			// {
			// 	Key: "k8s_cluster_name", Value: &cpb.AnyValue{
			// 		Value: &cpb.AnyValue_StringValue{StringValue: "TODO"},
			// 	},
			// },
			// {
			// 	Key: "interface-id", Value: &cpb.AnyValue{
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
	sonarEndpoint := fmt.Sprintf("https://networkflowmonitorreports.%s.api.aws/publish", option.Config.AWSSonarRegion)
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

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected response: %d %q", resp.StatusCode, body)
	}
	logger.GetLogger().WithField("scopes-count", len(exportRequest.ResourceMetrics[0].ScopeMetrics)).Debug("Successfully posted metrics to Sonar.")

	return nil
}

func InitSonar(ctx context.Context) {
	// defined here to capture ctx
	sonarStats.getCollect = func(cache *lru.Cache[networkapi.TcpKey, networkapi.MsgSocketStats]) collectFn {
		return func() {
			sleep := time.Duration(rand.Int63n(2*sonarJitter.Milliseconds())) * time.Millisecond
			time.Sleep(sleep)

			// reset the metrics list
			scopeMetricsList = []*mpb.ScopeMetrics{}
			// set collection timestamp
			currentTs = uint64(time.Now().UnixNano())

			getRunTcpGC(addTCPMetricsForSocket, cache)()

			err := postMetrics(ctx)
			if err != nil {
				logger.GetLogger().WithError(err).Error("Failed to post metrics to Sonar")
			}

			// update last collection timestamp
			lastCollectTs = currentTs
		}
	}

	logger.GetLogger().Info("Enabling Sonar metrics push")
	if err := sonarStats.enable(sonarInterval - sonarJitter); err != nil {
		logger.GetLogger().WithError(err).Error("Failed to enable Sonar metrics push")
	}
}
