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
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"text/template"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/gdamore/tcell/v2"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/rivo/tview"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/xlab/treeprint"
	"golang.org/x/term"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/model"
	"github.com/isovalent/hubble-fgs/pkg/model/checker"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

var (
	host             bool
	namespaces       []string
	workloads        []string
	output           string
	celFiles         []string
	celExprs         []string
	celYAML          string
	appModelFilename string
	verbose          bool
	patch            bool
	check            bool
	ignoreInDiff     []string
	ignoreByteCounts = true
)

var tree = treeprint.New()

func containerStringer(cont *appModelV1.ApplicationContainer) string {
	truncated := cont.Id
	if len(truncated) > 12 {
		truncated = truncated[:12]
	}

	return fmt.Sprintf("%s %s(%s)", cont.Image, cont.Name, truncated)
}

func printTree(appModel *appModelV1.ApplicationModelEvent, host bool) error {
	// For each namespace collection find workload collections
	for _, ns := range appModel.ApplicationModel.Namespaces {
		nsTree := tree.AddBranch(ns.Name)
		for _, wl := range ns.Workloads {
			wlTree := nsTree.AddBranch(wl.Name)
			for _, cont := range wl.Containers {
				contTree := wlTree.AddBranch(containerStringer(cont))
				for _, p := range cont.Processes {
					bin := p.Name + " " + p.Arguments
					binaryBranch := contTree.AddBranch(bin)

					for _, conn := range p.Connections {
						childName := fmt.Sprintf("%s (tx: %d rx: %d drops: %d defaultDrop: %d defaultAllow: %d)",
							model.DestinationNameAppModel(conn.Destination),
							conn.Stats.TxBytes, conn.Stats.RxBytes, conn.Stats.TxDrops,
							conn.Stats.DefaultDropBytes, conn.Stats.DefaultAllowBytes)
						binaryBranch.AddBranch(childName)
					}
				}
			}
		}
	}
	if !host {
		fmt.Println(tree.String())
		return nil
	}
	hostTree := tree.AddBranch("host")
	for _, p := range appModel.ApplicationModel.Host.Processes {
		bin := p.Name + " " + p.Arguments
		binaryBranch := hostTree.AddBranch(bin)

		for _, conn := range p.Connections {
			childName := fmt.Sprintf("%s (tx: %d rx: %d drops: %d defaultDrop: %d defaultAllow: %d)",
				model.DestinationNameAppModel(conn.Destination),
				conn.Stats.TxBytes, conn.Stats.RxBytes, conn.Stats.TxDrops,
				conn.Stats.DefaultDropBytes, conn.Stats.DefaultAllowBytes)
			binaryBranch.AddBranch(childName)
		}
	}
	fmt.Println(tree.String())
	return nil
}

func printModel(appModel *appModelV1.ApplicationModelEvent) error {
	out, err := json.Marshal(appModel)
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func addProcessNodes(node *tview.TreeNode, processes []*appModelV1.ApplicationProcessGroup) {
	for _, ps := range processes {
		childName := ps.GetName()
		if ps.GetArguments() != "" {
			childName += fmt.Sprintf(" %s", ps.GetArguments())
		}
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

func addContainerNodes(node *tview.TreeNode, containers []*appModelV1.ApplicationContainer) {
	for _, cont := range containers {
		nodeName := containerStringer(cont)
		if len(cont.GetProcesses()) == 1 {
			nodeName += " (1 process)"
		} else if len(cont.GetProcesses()) > 0 {
			nodeName += fmt.Sprintf(" (%d processes)", len(cont.GetProcesses()))
		}
		child := tview.NewTreeNode(nodeName).
			SetReference(cont).
			SetSelectable(true).
			SetColor(tcell.ColorPurple)
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
			if len(wl.GetContainers()) == 1 {
				nodeName += " (1 container)"
			} else if len(wl.GetContainers()) > 0 {
				nodeName += fmt.Sprintf(" (%d containers)", len(wl.GetContainers()))
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
		addContainerNodes(node, val.GetContainers())
	case *appModelV1.ApplicationContainer:
		addProcessNodes(node, val.GetProcesses())
	case *appModelV1.ApplicationProcessGroup:
		for _, conn := range val.GetConnections() {
			childName := fmt.Sprintf("%s (tx: %d rx: %d drops: %d defaultDrop: %d defaultAllow: %d)",
				model.DestinationNameAppModel(conn.Destination),
				conn.Stats.TxBytes, conn.Stats.RxBytes, conn.Stats.TxDrops,
				conn.Stats.DefaultDropBytes, conn.Stats.DefaultAllowBytes)
			child := tview.NewTreeNode(childName).
				SetReference(conn).
				SetSelectable(true).
				SetColor(tcell.ColorAliceBlue)
			node.AddChild(child)
		}
	}
}

func printInteractiveTree(enableS3 bool, bucket string) error {
	appModel, err := getAppModel(enableS3, bucket)
	if err != nil {
		return err
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

type treeGetter interface {
	GetTree() (*appModelV1.ApplicationModelEvent, error)
}

type wrappedEvent struct {
	*appModelV1.ApplicationModelEvent
}

func (model *wrappedEvent) GetTree() (*appModelV1.ApplicationModelEvent, error) {
	return model.ApplicationModelEvent, nil
}

func getTreeHtml(w http.ResponseWriter, _ *http.Request, getter treeGetter) {
	tmpl, err := template.ParseFS(uiDir, "ui/index.html")
	if err != nil {
		io.WriteString(w, "couldn't read ui index.html")
		return
	}
	appModel, err := getter.GetTree()
	if err != nil {
		io.WriteString(w, "failed getting model")
		return
	}
	appModelJson, err := json.Marshal(appModel)
	if err != nil {
		io.WriteString(w, "couldn't serialize app model json")
		return
	}
	values := map[string]interface{}{
		"IPT_APP_MODEL_SCRIPT": fmt.Sprintf(
			"<script>window.IPT_APP_MODEL_JSON = %s</script>", string(appModelJson),
		),
	}
	tmpl.Execute(w, values)
}

func runBrowserTree(enableS3 bool, bucket string) error {
	ctx := context.Background()
	appModel, err := getAppModel(enableS3, bucket)
	if err != nil {
		return err
	}
	getter := &wrappedEvent{ApplicationModelEvent: appModel}

	srv := &http.Server{
		Addr:        ":3333",
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		getTreeHtml(w, r, getter)
	})

	fmt.Println("application model web ui is running on http://localhost:3333")
	errChan := make(chan error)
	go func() {
		errChan <- srv.ListenAndServe()
	}()
	<-ctx.Done()
	srv.Shutdown(ctx)
	return <-errChan
}

func getAppModel(enableS3 bool, bucket string) (*appModelV1.ApplicationModelEvent, error) {
	var err error
	ctx := context.Background()
	appModel := &appModelV1.ApplicationModelEvent{}
	fi, _ := os.Stdin.Stat()
	if fi.Mode()&os.ModeNamedPipe != 0 {
		decoder := json.NewDecoder(bufio.NewReader(os.Stdin))
		err := decoder.Decode(&appModel)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	} else if enableS3 {
		config, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, err
		}
		client := s3.NewFromConfig(config, func(o *s3.Options) {
			o.DisableLogOutputChecksumValidationSkipped = true
		})
		last, err := s3GetLastKey(ctx, client, bucket, "")
		if err != nil {
			return nil, err
		}
		appModel, err = getS3Model(ctx, client, bucket, last, namespaces)
		if err != nil {
			return nil, err
		}
	} else if appModelFilename != "" {
		appModel, err = readAppModelFromFile(appModelFilename)
		if err != nil {
			return nil, err
		}
	} else {
		c, err := NewApplicationModelClient(context.Background())
		if err != nil {
			return nil, err
		}
		defer c.Close()

		req := &appModelV1.GetModelRequest{}
		resp, err := c.Client.GetModel(c.Ctx, req)
		if err != nil {
			return nil, err
		}
		appModel = resp.Model
	}

	return appModel, nil
}

func printGrpcTree(enableS3, host bool, bucket string) error {
	appModel, err := getAppModel(enableS3, bucket)
	if err != nil {
		return err
	}

	switch output {
	case "tree":
		return printTree(appModel, host)
	case "json":
		return printModel(appModel)
	default:
		return fmt.Errorf("invalid output format: %s", output)
	}
}

func checkProcessTree() (checker.ApplicationCheckerResult, error) {
	var err error
	var exprs []string

	ctx := context.Background()
	chk, err := checker.NewApplicationModelChecker()
	if err != nil {
		return nil, err
	}
	appModel, err := getAppModel(false, "")
	if err != nil {
		return nil, err
	}

	if len(celFiles) > 0 {
		for _, file := range celFiles {
			b, err := os.ReadFile(file)
			if err != nil {
				return nil, fmt.Errorf("error reading CEL file: %w", err)
			}
			exprs = append(exprs, string(b))
		}

	} else if len(celExprs) > 0 {
		exprs = celExprs
	} else if len(celYAML) > 0 {
		return chk.CheckApplicationModelYAML(ctx, appModel, celYAML)
	} else {
		return nil, fmt.Errorf("provide one of --expressions, --files, or --yaml")
	}
	return chk.CheckApplicationModelEvent(ctx, appModel, exprs)
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
	appModel, err := getAppModel(false, "")
	if err != nil {
		return "", err
	}

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

func readAppModelFromFile(filename string) (*appModelV1.ApplicationModelEvent, error) {
	var r io.Reader
	var err error
	if filename == "-" {
		r = os.Stdin
	} else {
		r, err = os.Open(filename)
		if err != nil {
			return nil, err
		}
	}

	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	model := &appModelV1.ApplicationModelEvent{}
	err = json.Unmarshal(b, model)
	if err != nil {
		return nil, err
	}

	return model, nil
}

func NewCheck() *cobra.Command {
	ret := &cobra.Command{
		Use:   "check [application model file]",
		Short: "Check the application model using CEL expressions",
		Example: `  # Check model.json using CEL checkers defined in source.cel
  tetra model check -f source.cel -m  model.json

  # Check an application model provided over gRPC for the node name "foo" and a bash process in namepsace "bar"
  tetra model check -e 'node_name == "foo" && model.namespaces.exists_one(n, n.name == "bar" && n.processes.exists_one(p, p.name.matches("/bash$")))'

  # Check an application model provided via stdin for a host process with 1337 bytes sent to a specific IP
  tetra model check -m - -e 'model.host.processes.exists_one(p, p.connections.exists(c, c.destination_name == "10.0.2.1" && c.bytes_sent == uint(1337)))'
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
				for i, failed := range v.Failed() {
					fmt.Printf("\tCheck %d: %q\n", i+1, failed)
				}
				os.Exit(-1)
				panic("unreachable")
			case *checker.ResultPass:
				fmt.Printf("✅ application model checks passed!\n")
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
	flags.StringVarP(&celYAML, "yaml", "y", "", "CEL expression(s) in YAML format")
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
  tetra model check generate -m model.json
  # Generate from stdin
  tetra model check generate -m -
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

func NewDiff() *cobra.Command {
	ret := &cobra.Command{
		Use:   "diff <model file> <model file>",
		Short: "Take the diff between two application model JSON files",
		Example: `  # Take the diff between two application models
  tetra model diff model-a.json model-b.json

  # Take the diff between two application models and print it as a JSON patch
  tetra model diff model-a.json model-b.json --patch

  # Check whether two models match
  tetra model diff model-a.json model-b.json --check
		`,
		Hidden:       false,
		SilenceUsage: false,
		Args:         cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			var opts []checker.Option
			// Ignore bytes in connections if ignoreByteCounts is set
			if ignoreByteCounts {
				opts = append(opts, checker.IgnoreFields(
					"namespaces.workloads.processes.connections.bytes_sent",
					"namespaces.workloads.processes.connections.bytes_received",
					"namespaces.workloads.processes.children.connections.bytes_sent",
					"namespaces.workloads.processes.children.connections.bytes_received",
					"host.processes.connections.bytes_sent",
					"host.processes.connections.bytes_received",
					"host.processes.children.connections.bytes_sent",
					"host.processes.children.connections.bytes_received",
				))
			}
			// Add custom ignores
			if len(ignoreInDiff) > 0 {
				opts = append(opts, checker.IgnoreFields(ignoreInDiff...))
			}
			// Print in color if we are printing to a terminal
			if term.IsTerminal(int(os.Stdout.Fd())) {
				opts = append(opts, checker.PrintColor())
			}
			if !verbose {
				opts = append(opts, checker.HideUnchanged())
			}

			a, err := readAppModelFromFile(args[0])
			if err != nil {
				return err
			}

			b, err := readAppModelFromFile(args[1])
			if err != nil {
				return err
			}

			if patch {
				diff, changed, err := checker.JsonDiff(a.ApplicationModel, b.ApplicationModel, opts...)
				if err != nil {
					return err
				}

				fmt.Println(string(diff))

				if check && changed {
					os.Exit(-1)
				}
			} else {
				diff, err := checker.PrettyJsonDiff(a.ApplicationModel, b.ApplicationModel, opts...)
				if err != nil {
					return err
				}

				if len(diff) == 0 {
					fmt.Println("No differences to report.")
				} else {
					fmt.Println(diff)
				}

				if check {
					if len(diff) > 0 {
						fmt.Printf("❌ application model checks failed!\n")
						os.Exit(-1)
					}
					fmt.Printf("✅ application model checks passed!")
				}
			}
			return nil
		},
	}

	flags := ret.Flags()
	flags.BoolVarP(&check, "check", "c", check, "Exit with failure status when models do not match")
	flags.BoolVarP(&patch, "patch", "p", patch, "Output as a JSON patch")
	flags.BoolVarP(&verbose, "verbose", "v", patch, "Print all fields when pretty printing")
	flags.BoolVar(&ignoreByteCounts, "ignore-byte-counts", ignoreByteCounts, "Convenience helper to ignore connection byte counts in diff")
	flags.StringArrayVarP(&ignoreInDiff, "ignore", "i", ignoreInDiff, "Field mask paths to ignore in the diff")
	viper.BindPFlags(flags)

	return ret
}

func NewShow() *cobra.Command {
	var s3 bool
	bucket := ""

	ret := &cobra.Command{
		Use:          "show",
		Short:        "Show application model using a gRPC connection or JSON",
		Hidden:       false,
		SilenceUsage: false,
		RunE: func(_ *cobra.Command, _ []string) error {
			switch output {
			case "interactive":
				return printInteractiveTree(s3, bucket)
			case "web":
				switch err := runBrowserTree(s3, bucket); err {
				case http.ErrServerClosed:
					fmt.Println("server closed")
					return nil
				default:
					return err
				}
			}
			return printGrpcTree(s3, host, bucket)
		},
	}

	flags := ret.Flags()
	flags.BoolVar(&s3, "s3", false, "S3 source")
	flags.StringVar(&bucket, "bucket", "appmodel", "S3 bucket source")
	flags.StringVarP(&output, "output", "o", "tree", "Specify the output format: tree|json|interactive|web")
	viper.BindPFlags(flags)

	return ret
}

func getProcessDebug() (*tetragon.GetProcessMapResponse, error) {
	c, err := NewConnectedModelClient(context.Background())
	if err != nil {
		return nil, err
	}
	defer c.Close()

	res, err := c.Client.GetProcessMap(c.Ctx, &tetragon.GetProcessMapRequest{})
	if err != nil || res == nil {
		logger.GetLogger().Warn("failed to get process map", logfields.Error, err)
		return nil, err
	}

	return res, nil
}

type sortableProcessDebug struct {
	p []*tetragon.ProcessUUID
}

func (s sortableProcessDebug) Less(x, y int) bool {
	return s.p[x].Id >= s.p[y].Id
}

func (s sortableProcessDebug) Len() int {
	return len(s.p)
}

func (s sortableProcessDebug) Swap(x, y int) {
	temp := s.p[x]
	s.p[x] = s.p[y]
	s.p[y] = temp
}

func printProcessDebug() error {
	res, err := getProcessDebug()
	if err != nil {
		return err
	}

	index := make([]*tetragon.ProcessUUID, 0, len(res.Map.Process))

	index = append(index, res.Map.Process...)

	s := sortableProcessDebug{
		p: index,
	}
	sort.Sort(s)

	for _, p := range s.p {
		children := ""
		for _, parent := range p.Children {
			children = children + " " + parent.Binary
		}
		fmt.Printf("%d(%d): [%s %s] -> {%s }\n", p.Id, p.Depth, p.Binary, p.Args, children)
	}
	return nil
}

func NewDebugProcess() *cobra.Command {
	ret := &cobra.Command{
		Use:          "process",
		Short:        "Debug the process state internal to the agent",
		Hidden:       false,
		SilenceUsage: false,
		RunE: func(_ *cobra.Command, _ []string) error {
			return printProcessDebug()
		},
	}

	flags := ret.Flags()
	flags.StringVarP(&output, "output", "o", "tree", "Specify the output format: tree|json|model")
	viper.BindPFlags(flags)

	return ret
}

func getDestinationDebug() (*tetragon.GetDestinationMapResponse, error) {
	c, err := NewConnectedModelClient(context.Background())
	if err != nil {
		return nil, err
	}
	defer c.Close()

	res, err := c.Client.GetDestinationMap(c.Ctx, &tetragon.GetDestinationMapRequest{})
	if err != nil || res == nil {
		logger.GetLogger().Warn("failed to get destination map", logfields.Error, err)
		return nil, err
	}

	return res, nil
}

func printDestinationDebug() error {
	res, err := getDestinationDebug()
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "LocalNSID\tLocalID\tDest ID:Src(Port)[Src]\tTxQuota\tTxLimit\tTxDrop\tDefaultDrop\tDefaultAllow\tPolicy")

	// Implementing a full Stringer on a proper type is more annoying that helpful
	// for this simple uint64, let's just use a custom local stringer for this
	// specific use case.
	destinationSourceStringer := func(source uint64) string {
		switch source {
		case types.DestinationSourceBPF:
			return "bpf"
		case types.DestinationSourceUser:
			return "user"
		case types.DestinationSourceDNS:
			return "dns"
		}
		return "unknown"
	}

	for _, d := range res.Destinations {
		fmt.Fprintf(w, "%d\t%d\t%d:%d(%d)[%s]\t%d\t%d\t%d\t%d\t%d\t%s\n",
			d.LocalNsId,
			d.LocalId,
			d.DestinationId,
			d.DestinationSource,
			d.DestinationPort,
			destinationSourceStringer(d.DestinationSource),
			d.TxQuota,
			d.TxLimit,
			d.TxDrops,
			d.DefaultDenyBytes,
			d.DefaultAllowBytes,
			d.Policy,
		)
	}
	return w.Flush()
}

func NewDebugDestination() *cobra.Command {
	ret := &cobra.Command{
		Use:          "destination",
		Short:        "Debug the destination key state internal to the agent",
		Hidden:       false,
		SilenceUsage: false,
		RunE: func(_ *cobra.Command, _ []string) error {
			return printDestinationDebug()
		},
	}

	flags := ret.Flags()
	flags.StringVarP(&output, "output", "o", "tree", "Specify the output format: tree|json|model")
	viper.BindPFlags(flags)

	return ret
}

func getDebug() (*tetragon.GetEndpointMapResponse, error) {
	c, err := NewConnectedModelClient(context.Background())
	if err != nil {
		return nil, err
	}
	defer c.Close()

	res, err := c.Client.GetEndpointMap(c.Ctx, &tetragon.GetEndpointMapRequest{})
	if err != nil || res == nil {
		logger.GetLogger().Warn("failed to get application model", logfields.Error, err)
		return nil, err
	}

	return res, nil
}

type sortableEndpoint struct {
	e []*tetragon.Endpoint
}

func (s sortableEndpoint) Less(x, y int) bool {
	return s.e[x].Key >= s.e[y].Key
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
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "Type\tID\tLocalIP\tValue")
	for _, e := range res.Map.Endpoints {
		fmt.Fprintf(w, "%s\t%d\t%s\t", strings.ToLower(strings.TrimPrefix(e.Type.String(), "ENDPOINT_TYPE_")), e.Key, e.SrcIP)
		switch e.Type {
		case tetragon.EndpointType_ENDPOINT_TYPE_DNS, tetragon.EndpointType_ENDPOINT_TYPE_BPF_DNS:
			fmt.Fprintf(w, "%s\t", e.Dns)
		case tetragon.EndpointType_ENDPOINT_TYPE_POD, tetragon.EndpointType_ENDPOINT_TYPE_SERVICE:
			fmt.Fprintf(w, "%s:%s(%s)\t", e.Namespace, e.Name, e.Kind)
		case tetragon.EndpointType_ENDPOINT_TYPE_IP:
			fmt.Fprintf(w, "%s\t", e.Ip)
		case tetragon.EndpointType_ENDPOINT_TYPE_LISTEN:
			fmt.Fprintf(w, "%s:%s\t", e.Ip, e.Port)
		case tetragon.EndpointType_ENDPOINT_TYPE_NODE:
			fmt.Fprintf(w, "%s(%s)\t", e.Name, e.Kind)
		case tetragon.EndpointType_ENDPOINT_TYPE_CIDR:
			fmt.Fprintf(w, "%s\t", e.Ip)
		default:
			fmt.Fprint(w, "unknown")
		}
		fmt.Fprintln(w, "")
	}

	return w.Flush()
}

func printEndpointDebug() error {
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

func NewDebugEndpoint() *cobra.Command {
	ret := &cobra.Command{
		Use:          "endpoint",
		Short:        "Debug the endpoint key state internal to the agent",
		Hidden:       false,
		SilenceUsage: false,
		RunE: func(_ *cobra.Command, _ []string) error {
			return printEndpointDebug()
		},
	}

	flags := ret.Flags()
	flags.StringVarP(&output, "output", "o", "tree", "Specify the output format: tree|json|model")
	viper.BindPFlags(flags)

	return ret
}

func NewDebug() *cobra.Command {
	ret := &cobra.Command{
		Use:          "debug",
		Short:        "Debug Tetragon application model",
		Hidden:       false,
		SilenceUsage: false,
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Help()
		},
	}

	ret.AddCommand(NewDebugProcess())
	ret.AddCommand(NewDebugDestination())
	ret.AddCommand(NewDebugEndpoint())

	pflags := ret.PersistentFlags()
	pflags.StringSliceVarP(&namespaces, "namespaces", "n", nil,
		"Get processes in specific namespaces. Specify '<host-namespace>' to list host processes.")
	pflags.StringSliceVar(&workloads, "workloads", nil, "Get tree by workload")
	pflags.BoolVar(&host, "host", false, "Include the tree for host")
	viper.BindPFlags(pflags)

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

func printAlerts(s3Enable bool, bucket string) error {
	alerts, counts, err := getAlertModel(s3Enable, bucket)
	if err != nil {
		return err
	}
	prettyPrintAlert(alerts, counts)
	return nil
}

func NewAlerts() *cobra.Command {
	var s3 bool
	bucket := ""

	ret := &cobra.Command{
		Use:          "alerts",
		Short:        "Show alerts using a gRPC connection or JSON",
		Hidden:       false,
		SilenceUsage: false,
		RunE: func(_ *cobra.Command, _ []string) error {
			return printAlerts(s3, bucket)
		},
	}

	flags := ret.Flags()
	flags.BoolVar(&s3, "s3", false, "S3 source")
	flags.StringVar(&bucket, "bucket", "appmodel", "S3 bucket source")
	viper.BindPFlags(flags)

	return ret
}

func New() *cobra.Command {
	ret := &cobra.Command{
		Use:          "model",
		Short:        "Tetragon application model",
		Hidden:       false,
		SilenceUsage: false,
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Help()
		},
	}

	ret.AddCommand(NewAlerts())
	ret.AddCommand(NewShow())
	ret.AddCommand(NewCheck())
	ret.AddCommand(NewDebug())
	ret.AddCommand(NewSquash())
	ret.AddCommand(NewDiff())

	pflags := ret.PersistentFlags()
	pflags.StringSliceVarP(&namespaces, "namespaces", "n", nil,
		"Get processes in specific namespaces. Specify '<host-namespace>' to list host processes.")
	pflags.StringSliceVar(&workloads, "workloads", nil, "Get tree by workload")
	pflags.BoolVar(&host, "host", false, "Include the tree for host")
	pflags.BoolVarP(&verbose, "verbose", "v", false, "Print all fields when pretty printing")
	viper.BindPFlags(pflags)

	return ret
}
