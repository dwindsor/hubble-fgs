//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	ec "github.com/isovalent/hubble-fgs/pkg/eventchecker"
	"github.com/isovalent/hubble-fgs/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/tests"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	checks = map[string]func(string) ec.MultiResponseChecker{
		"demo-app": tests.DemoAppChecker,
		"http":     tests.HttpChecker,
		"tls":      tests.TlsChecker,
	}

	kernelVersion   string
	serverAddresses []string
	check           string
	checkTimeout    uint32
	eventLimit      uint64

	rootCmd *cobra.Command
)

func rpcCheck(clients []fgs.FineGuidanceSensorsClient, checker ec.MultiResponseChecker,
	time_limit time.Duration, eventLimit uint64) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, unix.SIGINT, unix.SIGTERM)
		select {
		case <-sigs:
		case <-ctx.Done():
			signal.Stop(sigs)
		}
		cancel()
	}()

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
				if err != nil || ev == nil {
					logger.GetLogger().WithError(err).Fatal("Failed to receive event")
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
			case <-time.After(time_limit * time.Second):
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

func init() {
	rootCmd = &cobra.Command{
		Use:   "checkerpc",
		Short: "Run eventchecker over gRPC",
		RunE: func(cmd *cobra.Command, args []string) error {
			if check == "" {
				return fmt.Errorf("you must provide a value for --check\n%s", cmd.UsageString())
			}

			if checkFn, ok := checks[check]; ok {
				// Set up connect timeout (10s)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				// Connect to gRPC servers
				var wg sync.WaitGroup
				queue := make(chan *grpc.ClientConn, len(serverAddresses))
				wg.Add(len(serverAddresses))
				for _, serverAddress := range serverAddresses {
					go func(serverAddress string) {
						defer wg.Done()
						var conn *grpc.ClientConn
						var err error
						// retry up to 3 times
						for i := 0; i < 3; i++ {
							conn, err = grpc.DialContext(ctx, serverAddress, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
							if err == nil {
								break
							}
						}
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
				err := rpcCheck(clients, checkFn(kernelVersion), time.Duration(checkTimeout), eventLimit)
				if err != nil {
					fmt.Printf("🔥 %s check FAILED: no dice: %s\n", check, err)
					os.Exit(1)
				} else {
					fmt.Printf("🚢 %s check PASSED: ship it\n", check)
				}
				return nil
			}

			return fmt.Errorf("check \"%s\" is not in %v", check, reflect.ValueOf(checks).MapKeys())
		},
	}

	_, detectedVersion, _ := kernels.GetKernelVersion("", "/proc")

	flags := rootCmd.PersistentFlags()
	flags.StringArrayVar(&serverAddresses, "server-address", []string{"localhost:54321"}, "gRPC server address, can be specified more than once")
	flags.StringVar(&check, "check", "",
		fmt.Sprintf("check to perform, can be one of %v", reflect.ValueOf(checks).MapKeys()))
	flags.StringVar(&kernelVersion, "kernel", detectedVersion, "kernel version string under which the tests are running")
	flags.Uint32Var(&checkTimeout, "timeout", 300, "timeout in seconds for running checks, 0 implies no time limit")
	flags.Uint64Var(&eventLimit, "events", 1000000, "maximum number of events to check, 0 implies no limit")
	viper.BindPFlags(flags)
}

func checkerpcMain() {
	rootCmd.Execute()
}
