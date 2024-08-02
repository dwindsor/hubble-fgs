// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package exec

import (

	// append enterprise filters

	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/xlab/treeprint"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	host       bool
	namespaces []string
)

type ConnectedModelClient struct {
	Client tetragon.ProcessModelServiceClient
	Ctx    context.Context
	conn   *grpc.ClientConn
	cancel context.CancelFunc
}

const (
	defaultServerAddress = "localhost:54321"
)

type daemonInfo struct {
	ServerAddr string `json:"server_address"`
}

func readActiveServerAddress(fname string) (string, error) {
	f, err := os.Open(fname)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var info daemonInfo
	if err := json.NewDecoder(f).Decode(&info); err != nil {
		return "", err
	}

	return info.ServerAddr, nil
}

func connect(_ context.Context) (*grpc.ClientConn, string, error) {
	// resolve ServerAdress: if flag set by user, use it, otherwise try to read
	// it from tetragon-info.json, if it doesn't exist, just use default value
	if common.ServerAddress == "" {
		var err error
		common.ServerAddress, err = readActiveServerAddress(defaults.InitInfoFile)
		// if address could not be found in tetragon-info.json file, use default
		if err != nil {
			common.ServerAddress = defaultServerAddress
			logger.GetLogger().WithField("ServerAddress", common.ServerAddress).Debug("connect to server using default value")
		} else {
			logger.GetLogger().WithFields(logrus.Fields{
				"InitInfoFile":  defaults.InitInfoFile,
				"ServerAddress": common.ServerAddress,
			}).Debug("connect to server using address in info file")
		}
	}

	conn, err := grpc.NewClient(common.ServerAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))

	return conn, common.ServerAddress, err
}

// Close cleanup resources, it closes the connection and cancel the context
func (c ConnectedModelClient) Close() {
	c.conn.Close()
	c.cancel()
}

var tree = treeprint.New()

func printTree(res *tetragon.GetProcessModelResponse) error {
	// Create namespaces collections
	nsCollections := make(map[string][]*tetragon.ProcessModel)
	nsPrintList := make(map[string]bool)

	for _, p := range res.Processes {
		ns, ok := nsCollections[p.Namespace]
		if ok {
			nsCollections[p.Namespace] = append(ns, p)
		} else {
			nsCollections[p.Namespace] = []*tetragon.ProcessModel{p}
		}
	}

	for _, n := range namespaces {
		nsPrintList[n] = true
	}

	// For each namespace collection find workload collections
	for n, r := range nsCollections {
		var nsStr string

		if n == "" {
			nsStr = "<host-namespace>"
		} else {
			nsStr = n
		}

		if _, ok := nsPrintList[n]; !ok && len(namespaces) > 0 {
			continue
		}

		nsTree := tree.AddBranch(nsStr)

		// Create workload collections
		wlCollections := make(map[string][]*tetragon.ProcessModel)
		for _, p := range r {
			wl, ok := wlCollections[p.Workload.Name]
			if ok {
				wlCollections[p.Workload.Name] = append(wl, p)
			} else {
				wlCollections[p.Workload.Name] = []*tetragon.ProcessModel{p}
			}
		}

		for wlStr, wlProcesses := range wlCollections {
			if wlStr == "" {
				wlStr = "<host-workload>"
			}

			wlTree := nsTree.AddBranch(wlStr)

			for _, p := range wlProcesses {
				path := ""
				if p.Binary != "" {
					path = fmt.Sprintf("%s:%s", p.Parent, p.Binary)
				} else {
					path = fmt.Sprintf("<wl-destinations>")
				}
				binaryBranch := wlTree.AddBranch(path)

				zeroDests := make(map[string]treeprint.Tree)

				for _, d := range p.Dest {
					txBytes := uint64(0)
					rxBytes := uint64(0)
					endptName := ""

					if d.Port != 0 {
						continue
					}

					if d.Stats != nil {
						txBytes = d.Stats.TxBytes
						rxBytes = d.Stats.RxBytes
					}

					if d.DestinationPod != nil {
						endptName = d.DestinationPod.String()
					}
					if len(d.DestinationNames) > 0 {
						if endptName != "" {
							endptName = fmt.Sprintf("%s %s", d.DestinationNames, endptName)
						} else {
							endptName = fmt.Sprintf("%s", d.DestinationNames)
						}
					}

					compact := fmt.Sprintf("%s      [tx: %d rx: %d]", endptName, txBytes, rxBytes)
					zeroDests[endptName] = binaryBranch.AddBranch(compact)
				}
				for _, d := range p.Dest {
					txBytes := uint64(0)
					rxBytes := uint64(0)
					endptName := ""

					if d.Port == 0 {
						continue
					}
					if d.Stats != nil {
						txBytes = d.Stats.TxBytes
						rxBytes = d.Stats.RxBytes
					}

					if d.DestinationPod != nil {
						endptName = d.DestinationPod.String()
					}
					if len(d.DestinationNames) > 0 {
						if endptName != "" {
							endptName = fmt.Sprintf("%s %s", d.DestinationNames, endptName)
						} else {
							endptName = fmt.Sprintf("%s", d.DestinationNames)
						}
					}
					compact := fmt.Sprintf("   (%d) [tx: %d rx: %d]", d.Port, txBytes, rxBytes)
					zeroDests[endptName].AddBranch(compact)
				}
			}
		}
	}
	fmt.Println(tree.String())
	return nil
}

// NewConnectedClient return a connected client to a tetragon server, caller
// must call Close() on the client. On failure to connect, this function calls
// Fatal() thus stopping execution.
func NewConnectedModelClient() ConnectedModelClient {
	c := ConnectedModelClient{}
	c.Ctx, c.cancel = signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	var serverAddr string
	var err error

	backoff := time.Second
	attempts := 0
	for {
		c.conn, serverAddr, err = connect(c.Ctx)
		if err != nil {
			if attempts < common.Retries {
				// Exponential backoff
				attempts++
				logger.GetLogger().WithField("server-address", serverAddr).WithField("attempts", attempts).WithError(err).Error("Connection attempt failed, retrying...")
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			logger.GetLogger().WithField("server-address", serverAddr).WithField("attempts", attempts).WithError(err).Fatal("Failed to connect to server")
		}
		break
	}

	c.Client = tetragon.NewProcessModelServiceClient(c.conn)
	return c
}
func printGrpcTree() {
	c := NewConnectedModelClient()
	defer c.Close()

	res, err := c.Client.GetProcessModel(c.Ctx, &tetragon.GetProcessModelRequest{})
	if err != nil || res == nil {
		logger.GetLogger().WithError(err).Warn("failed to list tracing policies:")
		return
	}

	printTree(res)
}

func New() *cobra.Command {
	verbose := uint32(math.MaxUint32)

	ret := &cobra.Command{
		Use:          "pstree",
		Short:        "Print process tree",
		Hidden:       false,
		SilenceUsage: false,
		Run: func(_ *cobra.Command, _ []string) {
			printGrpcTree()
		},
	}

	flags := ret.Flags()
	flags.Uint32Var(&verbose, "verbose", verbose, "verbose (0 slim, 1 networking)")
	flags.StringSliceVar(&namespaces, "namespaces", nil, "Get tree by Kubernetes namespaces")
	viper.BindPFlags(flags)

	return ret
}
