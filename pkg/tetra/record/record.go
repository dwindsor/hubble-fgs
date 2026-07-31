// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package record

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sigs.k8s.io/yaml"

	"github.com/isovalent/hubble-fgs/pkg/recorder"
	"github.com/isovalent/hubble-fgs/pkg/recorder/config"

	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

var (
	jsonFile    string
	outFileName string
	host        bool
	namespaces  []string
	processes   []string
	pods        []string
)

// recordJSON records an event checker from a JSON export file.
func recordJSON(jsonFile string, conf *config.GenericRecorderConf, out *os.File) error {
	file, err := os.Open(jsonFile)
	if err != nil {
		return fmt.Errorf("failed to open `%s`: %w", jsonFile, err)
	}

	rec := recorder.NewRecorder(&conf.Spec)

	dec := json.NewDecoder(file)
	for dec.More() {
		var ev tetragon.GetEventsResponse
		if err := dec.Decode(&ev); err != nil {
			return fmt.Errorf("unmarshal failed: %w", err)
		}
		if err := rec.RecordResponse(&ev); err != nil {
			return fmt.Errorf("recording event failed: %w", err)
		}
	}

	checker := rec.Finish()
	b, err := yaml.Marshal(checker)
	if err != nil {
		return fmt.Errorf("marshal failed: %w", err)
	}
	out.Write(b)

	return nil
}

func getRequest(namespaces []string, host bool, processes []string, pods []string) *tetragon.GetEventsRequest {
	if host {
		// Host events can be matched by an empty namespace string.
		namespaces = append(namespaces, "")
	}
	return &tetragon.GetEventsRequest{
		AllowList: []*tetragon.Filter{{
			BinaryRegex: processes,
			Namespace:   namespaces,
			PodRegex:    pods,
		}},
	}
}

// recordGRPC records an event checker from a gRPC event stream.
func recordGRPC(ctx context.Context, client tetragon.FineGuidanceSensorsClient, conf *config.GenericRecorderConf, out *os.File) error {
	rec := recorder.NewRecorder(&conf.Spec)

	request := getRequest(namespaces, host, processes, pods)
	stream, err := client.GetEvents(ctx, request)
	if err != nil {
		logger.Fatal(logger.GetLogger(), "Failed to call GetEvents", logfields.Error, err)
	}
	for {
		res, err := stream.Recv()
		if err != nil {
			if !errors.Is(err, context.Canceled) && status.Code(err) != codes.Canceled {
				return err
			}
			break
		}
		if err = rec.RecordResponse(res); err != nil {
			logger.Fatal(logger.GetLogger(), "Failed to record event", logfields.Error, err, "event", res)
		}
	}

	checker := rec.Finish()
	b, err := yaml.Marshal(checker)
	if err != nil {
		return fmt.Errorf("marshal failed: %w", err)
	}
	out.Write(b)

	return nil
}

func New() *cobra.Command {
	cmd := cobra.Command{
		Use:   "record <config.yaml>",
		Short: "Record event checker",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return fmt.Errorf("requires a recorder config: %w", err)
			}
			if err := validateFileArg(args[0]); err != nil {
				return fmt.Errorf("invalid config.yaml file argument: %w", err)
			}
			return nil
		},
		PreRunE: func(_ *cobra.Command, _ []string) error {
			// Validate json file argument
			if jsonFile != "" {
				if err := validateFileArg(jsonFile); err != nil {
					return fmt.Errorf("invalid JSON file argument: %w", err)
				}
			}
			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			config, err := config.FileConfigYaml(args[0])
			if err != nil {
				return fmt.Errorf("failed to parse recorder config: %v", err)
			}

			var outFile *os.File
			if outFileName == "" {
				outFile = os.Stdout
			} else {
				outFile, err = os.Create(outFileName)
				if err != nil {
					return fmt.Errorf("failed to open output file for writing: %v", err)
				}
			}

			// If jsonFile is provided then don't try to connect to gRPC, just record
			// using the json file instead
			if jsonFile != "" {
				if err = recordJSON(jsonFile, config, outFile); err != nil {
					return fmt.Errorf("ailed to record event from JSON file: %v", err)
				}
			} else {
				client, err := common.NewClientWithDefaultContextAndAddress()
				if err != nil {
					return err
				}
				defer client.Close()
				if err = recordGRPC(client.Ctx, client.Client, config, outFile); err != nil {
					return fmt.Errorf("failed to record from gRPC: %v", err)
				}
			}
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&jsonFile, "json", "j", "", "Use JSON export file as the event source. Default is to use gRPC event stream instead.")
	flags.StringVarP(&outFileName, "out", "o", "", "Output file. Default is stdout")
	flags.StringSliceVarP(&namespaces, "namespace", "n", nil, "Get events by Kubernetes namespaces")
	flags.StringSliceVar(&processes, "process", nil, "Get events by process name regex")
	flags.StringSliceVar(&pods, "pod", nil, "Get events by pod name regex")
	flags.BoolVar(&host, "host", false, "Get host events")
	return &cmd
}

func validateFileArg(fileName string) error {
	if stat, err := os.Stat(fileName); err != nil {
		return fmt.Errorf("file name `%s` must be a valid path that exists: %w", fileName, err)
	} else if stat.IsDir() {
		return fmt.Errorf("file name `%s` must not be a directory", fileName)
	}
	return nil
}
