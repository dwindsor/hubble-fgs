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

	"bufio"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"syscall"
	"text/template"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/gdamore/tcell/v2"
	"github.com/isovalent/hubble-fgs/pkg/model"
	"github.com/isovalent/hubble-fgs/pkg/model/checker"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/rivo/tview"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/xlab/treeprint"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	host             bool
	namespaces       []string
	workloads        []string
	output           string
	celFiles         []string
	celExprs         []string
	appModelFilename string
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
	if d.DestinationService != nil {
		endptName = d.DestinationService.String()
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
	wlPrintList := make(map[string]bool)

	for _, p := range res.Processes {
		ns, ok := nsCollections[p.Namespace]
		if ok {
			nsCollections[p.Namespace] = append(ns, p)
		} else {
			nsCollections[p.Namespace] = []*tetragon.ProcessModel{p}
		}
	}

	for _, wl := range workloads {
		wlPrintList[wl] = true
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
			nsStr = model.HostNamespace
		} else {
			nsStr = n
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
				wlStr = model.HostWorkload
			}

			wlTree := nsTree.AddBranch(wlStr)

			for _, p := range wlProcesses {
				path := ""
				if p.Binary != "" {
					path = fmt.Sprintf("%s %s:%s %s", p.Parent, p.ParentArgs, p.Binary, p.BinaryArgs)
				} else {
					path = fmt.Sprintf(model.WorkloadDestinations)
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
					val, ok := zeroDests[endptName]
					if ok {
						stats := printStats(d)
						compact := fmt.Sprintf("%s[%s]", dstStr, stats)
						val.AddBranch(compact)
					}
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

func printModel(res *tetragon.GetProcessModelResponse) error {
	appModel := model.ProcessModelToApplicationModel(res)
	out, err := json.Marshal(appModel)
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func addProcessNodes(node *tview.TreeNode, processes []*appModelV1.ApplicationProcess) {
	for _, ps := range processes {
		childName := ps.GetName()
		if len(ps.GetConnections()) == 1 {
			childName += " (1 connection)"
		} else if len(ps.GetConnections()) > 0 {
			childName += fmt.Sprintf(" (%d connections)", len(ps.GetConnections()))
		}
		child := tview.NewTreeNode(childName).
			SetReference(ps).
			SetSelectable(true).
			SetColor(tcell.ColorGreen)
		node.AddChild(child)
	}
}

func selected(node *tview.TreeNode) {
	if len(node.GetChildren()) > 0 {
		// Toggle expand / collapse
		node.SetExpanded(!node.IsExpanded())
		return
	}
	switch val := node.GetReference().(type) {
	case *appModelV1.ApplicationModel:
		if len(val.GetNamespaces()) > 0 {
			namespaces := tview.NewTreeNode(fmt.Sprintf("%d namespaces", len(val.GetNamespaces()))).
				SetColor(tcell.ColorSnow).
				SetReference(val.GetNamespaces()).
				SetSelectable(true)
			node.AddChild(namespaces)
		}
		if len(val.GetHost().GetProcesses()) > 0 {
			host := tview.NewTreeNode(fmt.Sprintf("%d host processes", len(val.GetHost().GetProcesses()))).
				SetColor(tcell.ColorSnow).
				SetReference(val.GetHost()).
				SetSelectable(true)
			node.AddChild(host)
		}
	case []*appModelV1.ApplicationNamespace:
		for _, ns := range val {
			nodeName := ns.GetName()
			if len(ns.GetWorkloads()) == 1 {
				nodeName += " (1 workload)"
			} else if len(ns.GetWorkloads()) > 0 {
				nodeName += fmt.Sprintf(" (%d workloads)", len(ns.GetWorkloads()))
			}
			nsNode := tview.NewTreeNode(nodeName).
				SetReference(ns).
				SetSelectable(true).
				SetColor(tcell.ColorGreen)
			node.AddChild(nsNode)
		}
	case *appModelV1.ApplicationNamespace:
		for _, wl := range val.GetWorkloads() {
			nodeName := fmt.Sprintf("%s/%s", wl.GetKind(), wl.GetName())
			if len(wl.GetProcesses()) == 1 {
				nodeName += " (1 process)"
			} else if len(wl.GetProcesses()) > 0 {
				nodeName += fmt.Sprintf(" (%d processes)", len(wl.GetProcesses()))
			}
			wlNode := tview.NewTreeNode(nodeName).
				SetReference(wl).
				SetSelectable(true).
				SetColor(tcell.ColorSkyblue)
			node.AddChild(wlNode)
		}
	case *appModelV1.ApplicationHost:
		addProcessNodes(node, val.GetProcesses())
	case *appModelV1.ApplicationWorkload:
		addProcessNodes(node, val.GetProcesses())
	case *appModelV1.ApplicationProcess:
		for _, conn := range val.GetConnections() {
			childName := fmt.Sprintf("%s:%d", conn.GetDestinationName(), conn.GetDestinationPort())
			child := tview.NewTreeNode(childName).
				SetReference(conn).
				SetSelectable(true).
				SetColor(tcell.ColorAliceBlue)
			node.AddChild(child)
		}
	}
}

func printInteractiveTree() error {
	appModel := &appModelV1.ApplicationModelEvent{}
	fi, _ := os.Stdin.Stat()
	if fi.Mode()&os.ModeNamedPipe != 0 {
		decoder := json.NewDecoder(bufio.NewReader(os.Stdin))
		err := decoder.Decode(&appModel)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
	} else {
		res, err := getProcessTreeGrpc()
		if err != nil {
			return err
		}
		appModel = model.ProcessModelToApplicationModel(res)
	}
	root := tview.NewTreeNode("app_model").
		SetReference(appModel.GetApplicationModel()).
		SetColor(tcell.ColorSnow)
	tree := tview.NewTreeView().
		SetRoot(root).
		SetCurrentNode(root).
		SetSelectedFunc(selected)
	return tview.NewApplication().SetRoot(tree, true).EnableMouse(true).Run()
}

//go:embed ui
var uiDir embed.FS

func getTreeHtml(w http.ResponseWriter, _ *http.Request, appModel *appModelV1.ApplicationModelEvent) {
	tmpl, err := template.ParseFS(uiDir, "ui/index.html")
	if err != nil {
		io.WriteString(w, "couldn't read ui index.html")
		return
	}
	appModelJson, err := json.Marshal(appModel)
	if err != nil {
		io.WriteString(w, "couldn't serialize app model json")
		return
	}
	values := map[string]interface{}{
		"APP_MODEL_JSON": string(appModelJson),
	}
	tmpl.Execute(w, values)
}

func runBrowserTree() error {
	appModel := &appModelV1.ApplicationModelEvent{}

	fi, _ := os.Stdin.Stat()
	if fi.Mode()&os.ModeNamedPipe != 0 {
		decoder := json.NewDecoder(bufio.NewReader(os.Stdin))
		err := decoder.Decode(&appModel)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
	} else {
		res, err := getProcessTreeGrpc()
		if err != nil {
			return err
		}
		appModel = model.ProcessModelToApplicationModel(res)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		getTreeHtml(w, r, appModel)
	})

	fmt.Printf("pstree web ui is running on http://localhost:3333")
	return http.ListenAndServe(":3333", nil)
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

func getProcessTreeGrpc() (*tetragon.GetProcessModelResponse, error) {
	c := NewConnectedModelClient()
	defer c.Close()

	if host {
		namespaces = append(namespaces, model.HostNamespace)
	}
	res, err := getProcessModel(c, &tetragon.GetProcessModelRequest{
		Namespaces: namespaces,
		Debug:      common.Debug,
	})
	if err != nil || res == nil {
		logger.GetLogger().WithError(err).Warn("failed to get process tree")
		return nil, err
	}

	return res, nil
}

func printGrpcTree() error {
	res, err := getProcessTreeGrpc()
	if err != nil {
		return err
	}

	switch output {
	case "tree":
		return printTree(res)
	case "json":
		return printJSONTree(res)
	case "model":
		return printModel(res)
	default:
		return fmt.Errorf("invalid output format: %s", output)
	}
}

func getProcessModel(c ConnectedModelClient, req *tetragon.GetProcessModelRequest) (*tetragon.GetProcessModelResponse, error) {
	processModel := tetragon.GetProcessModelResponse{}
	res, err := c.Client.GetProcesses(c.Ctx, req)
	if err != nil || res == nil {
		return nil, err
	}
	for {
		proc, err := res.Recv()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		processModel.Processes = append(processModel.Processes, proc)
	}
	return &processModel, nil
}

func checkProcessTreeGrpc(ctx context.Context, chk *checker.ApplicationModelChecker) (checker.ApplicationCheckerResult, error) {
	c := NewConnectedModelClient()
	defer c.Close()

	if host {
		namespaces = append(namespaces, model.HostNamespace)
	}
	processModel, err := getProcessModel(c, &tetragon.GetProcessModelRequest{
		Namespaces: namespaces,
		Debug:      common.Debug,
	})
	if err != nil {
		return nil, err
	}
	appModel := model.ProcessModelToApplicationModel(processModel)

	return chk.CheckApplicationModelEvent(ctx, appModel)
}

func checkProcessTreeReader(ctx context.Context, reader io.Reader, chk *checker.ApplicationModelChecker) (checker.ApplicationCheckerResult, error) {
	b, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read application model: %w", err)
	}

	return chk.CheckApplicationModelEventJSON(ctx, string(b))
}

func checkProcessTree() (checker.ApplicationCheckerResult, error) {
	var appModelReader io.Reader
	var err error
	var chk *checker.ApplicationModelChecker

	ctx := context.Background()

	if len(celFiles) > 0 && len(celExprs) > 0 {
		return nil, fmt.Errorf("provide one of --files or --expressions but not both")
	}

	if len(celFiles) > 0 {
		exprs := []string{}
		for _, file := range celFiles {
			b, err := os.ReadFile(file)
			if err != nil {
				return nil, fmt.Errorf("error reading CEL file: %w", err)
			}
			exprs = append(exprs, string(b))
		}
		chk, err = checker.NewApplicationModelChecker(exprs)
		if err != nil {
			return nil, err
		}
	} else if len(celExprs) > 0 {
		chk, err = checker.NewApplicationModelChecker(celExprs)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("provide one of --files or --expressions")
	}

	if appModelFilename == "" {
		return checkProcessTreeGrpc(ctx, chk)
	}

	if appModelFilename == "-" {
		appModelReader = os.Stdin
	} else {
		fr, err := os.Open(appModelFilename)
		if err != nil {
			return nil, fmt.Errorf("failed to open app model file: %w", err)
		}
		appModelReader = fr
	}

	return checkProcessTreeReader(ctx, appModelReader, chk)
}

func generateChecker() (string, error) {
	var appModelReader io.Reader

	if appModelFilename == "" {
		return generateCheckerGrpc()
	}

	if appModelFilename == "-" {
		appModelReader = os.Stdin
	} else {
		fr, err := os.Open(appModelFilename)
		if err != nil {
			return "", fmt.Errorf("failed to open app model file: %w", err)
		}
		appModelReader = fr
	}

	return generateCheckerReader(appModelReader)
}

func generateCheckerGrpc() (string, error) {
	c := NewConnectedModelClient()
	defer c.Close()

	if host {
		namespaces = append(namespaces, model.HostNamespace)
	}
	res, err := c.Client.GetProcessModel(c.Ctx, &tetragon.GetProcessModelRequest{
		Namespaces: namespaces,
		Debug:      common.Debug,
	})
	if err != nil || res == nil {
		return "", err
	}

	appModel := model.ProcessModelToApplicationModel(res)

	return checker.GenerateCheckerCEL(appModel)
}

func generateCheckerReader(reader io.Reader) (string, error) {
	b, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("failed to read application model: %w", err)
	}

	appModel := &appModelV1.ApplicationModelEvent{}
	if err := protojson.Unmarshal(b, appModel); err != nil {
		return "", err
	}

	return checker.GenerateCheckerCEL(appModel)
}

func NewCheck() *cobra.Command {
	ret := &cobra.Command{
		Use:   "check [application model file]",
		Short: "Check the process tree application model using CEL expressions",
		Example: `  # Check model.json using CEL checkers defined in source.cel
  tetra pstree check -f source.cel -m  model.json

  # Check an application model provided over gRPC for the node name "foo" and a bash process in namepsace "bar"
  tetra pstree check -e 'node_name == "foo" && model.namespaces.exists_one(n, n.name == "bar" && n.processes.exists_one(p, p.name.matches("/bash$")))'

  # Check an application model provided via stdin for a host process with 1337 bytes sent to a specific IP
  tetra pstree check -m - -e 'model.host.processes.exists_one(p, p.connections.exists(c, c.destination_name == "10.0.2.1" && c.bytes_sent == uint(1337)))'
		`,
		Hidden:       false,
		SilenceUsage: false,
		RunE: func(_ *cobra.Command, _ []string) error {
			res, err := checkProcessTree()
			if err != nil {
				return err
			}
			switch v := res.(type) {
			case *checker.ResultFail:
				fmt.Printf("❌ application model checks failed:\n")
				for i, failed := range v.Failed {
					fmt.Printf("\tCheck %d: %q\n", i+1, failed)
				}
				os.Exit(-1)
				panic("unreachable")
			case *checker.ResultPass:
				fmt.Printf("✅ application model checks passed!")
				return nil
			default:
				panic("unhandled result")
			}
		},
	}

	ret.AddCommand(NewGenerate())

	flags := ret.Flags()
	flags.StringArrayVarP(&celFiles, "files", "f", celFiles, "CEL source file(s)")
	flags.StringArrayVarP(&celExprs, "expressions", "e", celFiles, "CEL expression(s)")
	viper.BindPFlags(flags)

	pflags := ret.PersistentFlags()
	pflags.StringVarP(&appModelFilename, "model", "m", appModelFilename, "Application model JSON file. Pass \"-\" to use stdin. If not provided, tetra will perform a gRPC query to get the application model.")
	viper.BindPFlags(pflags)

	return ret
}

func NewGenerate() *cobra.Command {
	ret := &cobra.Command{
		Use:   "generate",
		Short: "Generate an application model checker from application model JSON",
		Example: `  # Generate from a JSON file model.json
  tetra pstree check generate -m model.json
  # Generate from stdin
  tetra pstree check generate -m -
		`,
		Hidden:       false,
		SilenceUsage: false,
		RunE: func(_ *cobra.Command, _ []string) error {
			cel, err := generateChecker()
			if err != nil {
				return err
			}

			fmt.Println(cel)

			return nil
		},
	}

	return ret
}

func NewShow() *cobra.Command {
	ret := &cobra.Command{
		Use:          "show",
		Short:        "Show the process tree using a gRPC connection or application model JSON",
		Hidden:       false,
		SilenceUsage: false,
		RunE: func(_ *cobra.Command, _ []string) error {
			if output == "interactive" {
				return printInteractiveTree()
			} else if output == "web" {
				return runBrowserTree()
			}
			return printGrpcTree()
		},
	}

	flags := ret.Flags()
	flags.StringVarP(&output, "output", "o", "tree", "Specify the output format: tree|json|model|interactive|web")
	viper.BindPFlags(flags)

	return ret
}

func getDebug() (*tetragon.GetEndpointMapResponse, error) {
	c := NewConnectedModelClient()
	defer c.Close()

	res, err := c.Client.GetEndpointMap(c.Ctx, &tetragon.GetEndpointMapRequest{})
	if err != nil || res == nil {
		logger.GetLogger().WithError(err).Warn("failed to get process tree")
		return nil, err
	}

	return res, nil
}

type sortableEndpoint struct {
	e []*tetragon.Endpoint
}

func (s sortableEndpoint) Less(x, y int) bool {
	if s.e[x].Key < s.e[y].Key {
		return false
	}
	return true
}

func (s sortableEndpoint) Len() int {
	return len(s.e)
}

func (s sortableEndpoint) Swap(x, y int) {
	temp := s.e[x]
	s.e[x] = s.e[y]
	s.e[y] = temp
}

func printDebugJSON(res *tetragon.GetEndpointMapResponse) error {
	out, err := json.Marshal(res)
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func printDebugCompact(res *tetragon.GetEndpointMapResponse) error {
	fmt.Printf("LocalIP %14s EndpointId %12s EndpointValue\n", "", "")
	fmt.Printf("-------------------------------------------------------------\n")
	for _, e := range res.Map.Endpoints {
		ipLen := int(len(e.SrcIP))
		spaces := 15 - ipLen + 14
		keyStr := strconv.FormatUint(e.Key, 10)
		idSpaces := 2 - len(keyStr) + 14
		switch e.Type {
		case tetragon.EndpointType_Dnstype:
			fmt.Printf("%s%*c %d %*c %s\n", e.SrcIP, spaces, ' ', e.Key, idSpaces, ' ', e.Dns)
		case tetragon.EndpointType_PodType:
			fmt.Printf("%s%*c %d %*c %s:%s %s\n", e.SrcIP, spaces, ' ', e.Key, idSpaces, ' ', e.Namespace, e.Name, e.Kind)
		case tetragon.EndpointType_IpType:
			fmt.Printf("%s%*c %d %*c %s\n", e.SrcIP, spaces, ' ', e.Key, idSpaces, ' ', e.Ip)
		case tetragon.EndpointType_ServiceType:
			fmt.Printf("%s%*c %d %*c %s:%s %s\n", e.SrcIP, spaces, ' ', e.Key, idSpaces, ' ', e.Namespace, e.Name, e.Kind)
		case tetragon.EndpointType_ListenType:
			fmt.Printf("%s%*c %d %*c %s:%s\n", e.SrcIP, spaces, ' ', e.Key, idSpaces, ' ', e.Ip, e.Port)
		default:
			fmt.Printf("%s %14s %d unknownType\n", e.SrcIP, "", e.Key)
		}
	}
	return nil
}

func printDebug() error {
	res, err := getDebug()
	if err != nil {
		return err
	}

	s := sortableEndpoint{
		e: res.Map.Endpoints,
	}
	sort.Sort(s)
	res.Map.Endpoints = s.e

	switch output {
	/* Default output is tree use json for debug */
	case "tree":
		return printDebugCompact(res)
	case "json":
		return printDebugJSON(res)
	default:
		return fmt.Errorf("invalid output format: %s", output)
	}
}

func NewDebug() *cobra.Command {
	ret := &cobra.Command{
		Use:          "debug",
		Short:        "Debug the application model state internal to the agent",
		Hidden:       false,
		SilenceUsage: false,
		RunE: func(_ *cobra.Command, _ []string) error {
			return printDebug()
		},
	}

	flags := ret.Flags()
	flags.StringVarP(&output, "output", "o", "tree", "Specify the output format: tree|json|model")
	viper.BindPFlags(flags)

	return ret
}

func NewSquash() *cobra.Command {
	ret := &cobra.Command{
		Use:   "squash",
		Short: "Squash multiple application_model JSON inputs into one",
		RunE: func(_ *cobra.Command, _ []string) error {
			return squash()
		},
	}
	return ret
}

func squash() error {
	appModel := &appModelV1.ApplicationModel{}
	fi, _ := os.Stdin.Stat()
	if fi.Mode()&os.ModeNamedPipe != 0 {
		decoder := json.NewDecoder(bufio.NewReader(os.Stdin))
		for {
			var ev appModelV1.ApplicationModelEvent
			err := decoder.Decode(&ev)
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			appModel = model.Merge(appModel, ev.GetApplicationModel())
		}
		res := &appModelV1.ApplicationModelEvent{
			ApplicationModel: appModel,
		}
		appBytes, err := res.MarshalJSON()
		if err != nil {
			return err
		}
		fmt.Println(string(appBytes))
	}
	return nil
}

func New() *cobra.Command {
	ret := &cobra.Command{
		Use:          "pstree",
		Short:        "Tetragon process tree",
		Hidden:       false,
		SilenceUsage: false,
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Help()
		},
	}

	ret.AddCommand(NewShow())
	ret.AddCommand(NewCheck())
	ret.AddCommand(NewDebug())
	ret.AddCommand(NewSquash())

	pflags := ret.PersistentFlags()
	pflags.StringSliceVarP(&namespaces, "namespaces", "n", nil,
		"Get processes in specific namespaces. Specify '<host-namespace>' to list host processes.")
	pflags.StringSliceVar(&workloads, "workloads", nil, "Get tree by workload")
	pflags.BoolVar(&host, "host", false, "Include the tree for host")
	viper.BindPFlags(pflags)

	return ret
}
