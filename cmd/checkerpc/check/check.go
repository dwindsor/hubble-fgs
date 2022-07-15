//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package check

import (
	"context"
	"errors"
	"fmt"
	"time"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	ecYaml "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker/yaml"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/helpers"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/cmd/checkerpc/grpc"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RunChecks runs event checks over gRPC according to CLI options
func RunChecks(ctx context.Context, check, kernelVersion string, addrs []string, connectTimeout,
	checkTimeout time.Duration, eventLimit uint64) error {

	// Read checker yaml
	specData := map[string]interface{}{
		"isMin510": (kernels.KernelStringToNumeric(kernelVersion) >= kernels.KernelStringToNumeric("5.10")),
	}
	spec, err := ecYaml.ReadYamlFileTemplate(check, specData)
	if err != nil {
		return fmt.Errorf("Failed to read checker yaml file %s: %w", check, err)
	}
	checker, err := spec.Spec.IntoMultiEventChecker()
	if err != nil {
		return fmt.Errorf("Failed to convert spec %s to event checker: %w", check, err)
	}

	// Connect client(s)
	clients, err := grpc.Connect(ctx, connectTimeout, addrs...)
	if err != nil {
		return fmt.Errorf("Failed to spawn checker client(s): %w", err)
	}

	// Perform the checks
	logger.GetLogger().WithField("check", check).Info("Running event checks...")
	err = rpcCheck(ctx, clients, checker, checkTimeout, eventLimit)
	if err != nil {
		fmt.Printf("🔥 %s check FAILED: no dice: %s\n", check, err)
		return fmt.Errorf("checks failed: %w", err)
	}
	fmt.Printf("🚢 %s check PASSED: ship it\n", check)
	return nil
}

// rpcCheck is the internal implementation for RunChecks
func rpcCheck(ctx context.Context, clients *grpc.ClientMultiplexer, checker ec.MultiEventChecker,
	timeLimit time.Duration, eventLimit uint64) error {
	fieldLog := logger.GetLogger()
	log, ok := fieldLog.(*logrus.Logger)
	if !ok {
		return fmt.Errorf("failed to convert logger")
	}
	var eventCount uint64

	c := clients.GetEvents(ctx)
	timeout := time.After(timeLimit)
	for {
		select {
		case <-timeout:
			if timeLimit > 0 {
				return fmt.Errorf("Checker timeout exceeded")
			}
		case ev := <-c:
			err := ev.Error
			event := ev.GetEventsResponse

			if event == nil || err != nil && !errors.Is(err, context.Canceled) && status.Code(err) != codes.Canceled {
				return fmt.Errorf("Failed to receive event: %w", err)
			}

			if err == nil && errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled {
				return nil
			}

			eventCount++
			eventType, err := helpers.ResponseTypeString(event)
			if err != nil {
				log.Warnf("Failed to get event type: %v", err)
				eventType = "UNKNOWN"
			}
			prefix := fmt.Sprintf("%s:%d", eventType, eventCount)

			if eventLimit > 0 && eventCount > eventLimit {
				return fmt.Errorf("Event limit exceeded")
			}

			done, err := ec.NextResponseCheck(checker, event, log)
			if done && err == nil {
				log.Infof("%s => FINAL MATCH ", prefix)
				log.Infof("DONE!")
				return nil
			} else if err == nil {
				log.Infof("%s => MATCH, continuing", prefix)
			} else if done && err != nil {
				log.Errorf("%s => terminating error: %s", prefix, err)
				return err
			} else {
				log.Infof("%s => no match: %s, continuing", prefix, err)
			}
		}
	}
}
