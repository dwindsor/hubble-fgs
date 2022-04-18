//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package rpccheck

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/cmd/checkerpc/cli/flags"
	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/tests"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// CheckFn is a type alias for a function that takes a kernel version and returns an event
// checker for that kernel version
type CheckFn func(string) ec.MultiResponseChecker

// Checks is a mapping between check names and the associated CheckFn
var Checks = map[string]CheckFn{
	"demo-app": tests.DemoAppChecker,
	"http":     tests.HttpChecker,
	"tls":      tests.TlsChecker,
}

// RunChecks runs event checks over gRPC according to CLI options
func RunChecks(ctx context.Context) error {
	check := viper.GetString(flags.KeyCheck)
	checkFn := Checks[check]
	serverAddresses := viper.GetStringSlice(flags.KeyServerAddresses)
	connectTimeout := viper.GetDuration(flags.KeyConnectTimeout)
	kernelVersion := viper.GetString(flags.KeyKernelVersion)
	checkTimeout := viper.GetDuration(flags.KeyEventsTimeout)
	eventLimit := viper.GetUint64(flags.KeyEventsLimit)

	// Set up connect timeout (10s)
	connCtx, connCancel := context.WithTimeout(ctx, connectTimeout)
	defer connCancel()

	// Connect to gRPC servers
	var wg sync.WaitGroup
	queue := make(chan *grpc.ClientConn, len(serverAddresses))
	wg.Add(len(serverAddresses))
	for _, serverAddress := range serverAddresses {
		logger.GetLogger().WithField("addr", serverAddress).Info("Connecting to gRPC server...")
		go func(serverAddress string) {
			defer wg.Done()
			conn, err := grpc.DialContext(connCtx, serverAddress, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
			if err != nil {
				logger.GetLogger().WithError(err).Error("Failed to connect")
				os.Exit(1)
			}
			queue <- conn
			logger.GetLogger().WithField("addr", serverAddress).Info("Connected to gRPC server")
		}(serverAddress)
	}

	go func() {
		wg.Wait()
		close(queue)
	}()

	// Pull connections out of channel
	var conns []*grpc.ClientConn
	for conn := range queue {
		conns = append(conns, conn)
	}

	// Splitting this up into a separate for-loop means the defer doesn't
	// depend on closing the channel (otherwise go lint complains)
	var clients []fgs.FineGuidanceSensorsClient
	for _, conn := range conns {
		clients = append(clients, fgs.NewFineGuidanceSensorsClient(conn))
		defer conn.Close()
	}

	// Perform the checks
	logger.GetLogger().WithField("check", check).Info("Running event checks...")
	err := rpcCheck(ctx, clients, checkFn(kernelVersion), checkTimeout, eventLimit)
	if err != nil {
		fmt.Printf("🔥 %s check FAILED: no dice: %s\n", check, err)
		return fmt.Errorf("checks failed: %w", err)
	}
	fmt.Printf("🚢 %s check PASSED: ship it\n", check)
	return nil
}

// rpcCheck is the internal implementation for RunChecks
func rpcCheck(ctx context.Context, clients []fgs.FineGuidanceSensorsClient, checker ec.MultiResponseChecker,
	time_limit time.Duration, eventLimit uint64) error {

	log := &ec.LogrusLogger{L: logrus.New()}
	eventCount := new(uint64)
	var mutex sync.Mutex

	c := make(chan error)

	// Spawn a goroutine for each active client, checking events in parellel.
	// We maintain a shared event counter for logging purposes + enforcing
	// an event limit.
	for _, client := range clients {
		stream, err := client.GetEvents(ctx, &fgs.GetEventsRequest{})
		if err != nil {
			logger.GetLogger().WithError(err).Fatal("Failed to call GetEvents")
		}
		go func(stream fgs.FineGuidanceSensors_GetEventsClient) {
			for {
				ev, err := stream.Recv()
				if ev == nil || err != nil && !errors.Is(err, context.Canceled) && status.Code(err) != codes.Canceled {
					logger.GetLogger().WithError(err).Warn("Failed to receive event")
					c <- err
					return
				}

				atomic.AddUint64(eventCount, 1)
				count := atomic.LoadUint64(eventCount)
				prefix := fmt.Sprintf("rpcCheck/event:%04d", count)

				if eventLimit > 0 && count > eventLimit {
					log.Logf("%s => event limit exceeded", prefix)
					c <- fmt.Errorf("event limit exceeded")
					return
				}

				// NextCheck might mutate the internal state of the checker, so let's
				// guard it with a mutex
				mutex.Lock()
				done, err := checker.NextCheck(ev, log)
				mutex.Unlock()
				if done && err == nil {
					log.Logf("%s => FINAL MATCH ", prefix)
					log.Logf("DONE!")
					c <- nil
					return
				} else if err == nil {
					log.Logf("%s => MATCH, continuing", prefix)
				} else if done && err != nil {
					log.Logf("%s => terminating error: %s", prefix, err)
					c <- err
					return
				} else {
					if _, ok := err.(ec.EventTypeError); !ok {
						log.Logf("%s => no match: %s, continuing", prefix, err)
					}
				}
			}
		}(stream)
	}

	for {
		// Unclear if there is a better way to do this, but we only want to check
		// the timeout condition if timeout is actually > 0
		if time_limit > 0 {
			select {
			case err := <-c:
				return err
			case <-time.After(time_limit):
				return fmt.Errorf("checker timeout exceeded")
			}
		} else {
			select {
			case err := <-c:
				return err
			}
		}
	}
}
