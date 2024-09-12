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
	"sort"
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
	workloads  []string
	output     string

	hostNamespace = "<host-namespace>"
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

func printDestination(d *tetragon.Destination) (string, string) {
	endptName := ""
	dst := ""

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

	if d.Port != 0 {
		dst = fmt.Sprintf("%s   (%d) ", endptName, d.Port)
	} else {
		dst = fmt.Sprintf("%s ", endptName)
	}
	return endptName, dst
}

func printStats(d *tetragon.Destination) string {
	stats := ""

	if d.Stats == nil {
		return stats
	}

	if d.Stats.TxLimit > 0 {
		stats = fmt.Sprintf("tx: %d rx: %d drops: %d limit: %d", d.Stats.TxBytes, d.Stats.RxBytes, d.Stats.TxDrops, d.Stats.TxLimit)
	} else {
		stats = fmt.Sprintf("tx: %d rx: %d", d.Stats.TxBytes, d.Stats.RxBytes)
	}
	return stats
}

func printTree(res *tetragon.GetProcessModelResponse) error {
	// Create namespaces collections
	nsCollections := make(map[string][]*tetragon.ProcessModel)
	nsPrintList := make(map[string]bool)
	wlPrintList := make(map[string]bool)

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

	for _, wl := range workloads {
		wlPrintList[wl] = true
	}

	if host {
		nsPrintList[hostNamespace] = true
	}

	nsKeys := make([]string, 0, len(nsCollections))
	for nsKey := range nsCollections {
		nsKeys = append(nsKeys, nsKey)
	}
	sort.Strings(nsKeys)

	// For each namespace collection find workload collections
	for _, k := range nsKeys {
		var nsStr string

		n := k
		r := nsCollections[k]

		if n == "" {
			nsStr = hostNamespace
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
			wlName := fmt.Sprintf("%s:%s", p.Workload.Kind, p.Workload.Name)

			if _, ok := wlPrintList[wlName]; !ok && len(workloads) > 0 {
				continue
			}

			wl, ok := wlCollections[wlName]
			if ok {
				wlCollections[wlName] = append(wl, p)
			} else {
				wlCollections[wlName] = []*tetragon.ProcessModel{p}
			}
		}

		wlKeys := make([]string, 0, len(wlCollections))
		for key := range wlCollections {
			wlKeys = append(wlKeys, key)
		}
		sort.Strings(wlKeys)

		for _, key := range wlKeys {
			wlStr := key
			wlProcesses := wlCollections[key]

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
					if d.Port != 0 {
						continue
					}

					endptName, dstStr := printDestination(d)
					stats := printStats(d)
					compact := fmt.Sprintf("%s[%s]", dstStr, stats)
					zeroDests[endptName] = binaryBranch.AddBranch(compact)
				}
				for _, d := range p.Dest {
					if d.Port == 0 {
						continue
					}
					endptName, dstStr := printDestination(d)
					stats := printStats(d)
					compact := fmt.Sprintf("%s[%s]", dstStr, stats)
					zeroDests[endptName].AddBranch(compact)
				}
			}
		}
	}
	fmt.Println(tree.String())
	return nil
}

func printJSONTree(res *tetragon.GetProcessModelResponse) error {
	out, err := res.MarshalJSON()
	if err != nil {
		return err
	}
	fmt.Println(string(out))
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
func printGrpcTree() error {
	c := NewConnectedModelClient()
	defer c.Close()

	res, err := c.Client.GetProcessModel(c.Ctx, &tetragon.GetProcessModelRequest{})
	if err != nil || res == nil {
		logger.GetLogger().WithError(err).Warn("failed to list tracing policies:")
		return err
	}

	switch output {
	case "tree":
		return printTree(res)
	case "json":
		return printJSONTree(res)
	default:
		return fmt.Errorf("invalid output format: %s", output)
	}
}

func New() *cobra.Command {
	verbose := uint32(math.MaxUint32)

	ret := &cobra.Command{
		Use:          "pstree",
		Short:        "Print process tree",
		Hidden:       false,
		SilenceUsage: false,
		RunE: func(_ *cobra.Command, _ []string) error {
			return printGrpcTree()
		},
	}

	flags := ret.Flags()
	flags.Uint32Var(&verbose, "verbose", verbose, "verbose (0 slim, 1 networking)")
	flags.StringSliceVarP(&namespaces, "namespaces", "n", nil, "Get tree by Kubernetes namespaces")
	flags.StringSliceVar(&workloads, "workloads", nil, "Get tree by workload")
	flags.StringVarP(&output, "output", "o", "tree", "Specify the output format: tree|json")
	flags.BoolVar(&host, "host", false, "Include the tree for host")
	viper.BindPFlags(flags)

	return ret
}
