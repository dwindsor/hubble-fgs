//go:build sudo_tests

package recordbpftest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/datapath"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	model "github.com/isovalent/hubble-fgs/pkg/model/server"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/exec/procevents"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/cgroup"
	"github.com/stretchr/testify/require"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
)

var (
	prog datapath.Interface = &datapath.BpfProgrammer{}
)

type recordCheck struct {
	check string
}

type recordTest struct {
	name    string
	records []*record.DatapathRecord
	checks  []recordCheck
	deny    bool
}

// Policy record building blocks
var (
	wildcardSrc = &types.ProcessTreeKey{
		NSID:  uint64(policyfilter.StateID(0)),
		Depth: 0,
		Self:  0,
		Path:  [8]uint64{0, 0, 0, 0, 0, 0, 0, 0},
	}

	ipLo1Policy = &record.DatapathRecord{
		Policy: record.Policy{
			Name: "testPolicy1",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				Ip:   "127.0.0.1/32",
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyDeny,
		},
	}
	ipLo1AllowPolicy = &record.DatapathRecord{
		Policy: record.Policy{
			Name: "testPolicyAllow1",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				Ip:   "127.0.0.1/32",
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyAllow,
		},
	}
	ipLo2Policy = &record.DatapathRecord{
		Policy: record.Policy{
			Name: "testPolicy2",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				Ip:   "127.0.0.2/32",
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyDeny,
		},
	}
	ipLo2AllowPolicy = &record.DatapathRecord{
		Policy: record.Policy{
			Name: "testPolicyAllow2",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				Ip:   "127.0.0.2/32",
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyAllow,
		},
	}
	ipLo3Policy = &record.DatapathRecord{
		Policy: record.Policy{
			Name: "testPolicy3",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				Ip:   "127.0.0.0/24",
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyDeny,
		},
	}
	ipLo3AllowPolicy = &record.DatapathRecord{
		Policy: record.Policy{
			Name: "testPolicyAllow3",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				Ip:   "127.0.0.0/24",
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyAllow,
		},
	}
	dnsLoDenyPolicy = &record.DatapathRecord{
		Policy: record.Policy{
			Name: "testPolicyDNSDeny",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_DNS,
				Dns:  "localhost",
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyDeny,
		},
	}
	dnsLoDenyFooPolicy = &record.DatapathRecord{
		Policy: record.Policy{
			Name: "testPolicyDNSDeny",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_DNS,
				Dns:  "foo.io",
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyDeny,
		},
	}
	dnsLoAllowPolicy = &record.DatapathRecord{
		Policy: record.Policy{
			Name: "testPolicyDNSAllow",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_DNS,
				Dns:  "localhost",
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyAllow,
		},
	}
	podDenyPolicy = &record.DatapathRecord{
		Policy: record.Policy{
			Name: "testPolicyPod",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type:      tetragon.EndpointType_ENDPOINT_TYPE_POD,
				Kind:      "bpfTestKind",
				Namespace: "bpfTestNamespace",
				Name:      "bpfTestName",
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyDeny,
		},
	}
	podAllowPolicy = &record.DatapathRecord{
		Policy: record.Policy{
			Name: "testPolicyPod",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type:      tetragon.EndpointType_ENDPOINT_TYPE_POD,
				Kind:      "bpfTestKind",
				Namespace: "bpfTestNamespace",
				Name:      "bpfTestName",
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyAllow,
		},
	}
)

// checks
var (
	curl       = []recordCheck{recordCheck{check: "curl"}}
	digAndCurl = []recordCheck{recordCheck{check: "dig"}, recordCheck{check: "curl"}}
)

var tests = []recordTest{
	{ // Basic /32 hit and deny
		name:    "testDenyLo",
		records: []*record.DatapathRecord{ipLo1Policy},
		checks:  curl,
		deny:    true,
	},
	{ // Test basic /32 deny record when a unspec entry exists in the dest map for a tuple
		name:    "testDenyLoDup",
		records: []*record.DatapathRecord{ipLo1Policy},
		checks:  curl,
		deny:    true,
	},
	{ // policy deny miss for a different IP
		name:    "testMissDenyLo",
		records: []*record.DatapathRecord{ipLo2Policy},
		checks:  curl,
		deny:    false,
	},
	{ // policy allow miss for a different IP
		name:    "testMissAllowLo",
		records: []*record.DatapathRecord{ipLo2AllowPolicy},
		checks:  curl,
		deny:    false,
	},
	{ // policy deny for /24
		name:    "testDenyLo/24",
		records: []*record.DatapathRecord{ipLo3Policy},
		checks:  curl,
		deny:    true,
	},
	{ // policy allow for /24
		name:    "testAllowLo/24",
		records: []*record.DatapathRecord{ipLo3AllowPolicy},
		checks:  curl,
		deny:    false,
	},
	{ // policy deny ignores dns and drops connect
		name:    "testIgnoreDigWithCIDRLo",
		records: []*record.DatapathRecord{ipLo1Policy},
		checks:  digAndCurl,
		deny:    true,
	},
	{ // policy allow ignores dns and allows connect
		name:    "testIgnoreDigWithCIDRLo",
		records: []*record.DatapathRecord{ipLo1AllowPolicy},
		checks:  digAndCurl,
		deny:    false,
	},
	{ // basic localhost dns deny connect
		name:    "testDigDenyLo",
		records: []*record.DatapathRecord{dnsLoDenyPolicy},
		checks:  digAndCurl,
		deny:    true,
	},
	{ // basic miss foo dns allow connect
		name:    "testDigDenyFooLo",
		records: []*record.DatapathRecord{dnsLoDenyFooPolicy},
		checks:  digAndCurl,
		deny:    false,
	},
	{ // basic localhost dns allow connect
		name:    "testDigAllowLo",
		records: []*record.DatapathRecord{dnsLoAllowPolicy},
		checks:  digAndCurl,
		deny:    false,
	},
	{ // test conflicting policy and dns deny wins
		name:    "testCIDRandDNSDeny",
		records: []*record.DatapathRecord{dnsLoDenyPolicy, ipLo1AllowPolicy},
		checks:  digAndCurl,
		deny:    true,
	},
	{ // test conflicting policy and cidr deny wins
		name:    "testDNSandCIDRDeny",
		records: []*record.DatapathRecord{dnsLoAllowPolicy, ipLo1Policy},
		checks:  digAndCurl,
		deny:    true,
	},
	{ // test two allow policy and cidr and dns so allow wins
		name:    "testDNSwithCIDRAllow",
		records: []*record.DatapathRecord{dnsLoAllowPolicy, ipLo1AllowPolicy},
		checks:  digAndCurl,
		deny:    false,
	},
	{ // test two deny policy and cidr and dns so deny wins
		name:    "testDNSwithCIDRDeny",
		records: []*record.DatapathRecord{dnsLoDenyPolicy, ipLo1Policy},
		checks:  digAndCurl,
		deny:    true,
	},
	{ // test basic Pod deny policy
		name:    "testPodDeny",
		records: []*record.DatapathRecord{podDenyPolicy},
		checks:  curl,
		deny:    true,
	},
	{ // test basic Pod allow policy
		name:    "testPodAllow",
		records: []*record.DatapathRecord{podAllowPolicy},
		checks:  curl,
		deny:    false,
	},
}

func loadRecords(r *recordTest, t *testing.T) {
	for _, rec := range r.records {
		if rec.Endpoint.EP == nil {
			continue
		}
		if rec.Endpoint.EP.Type == tetragon.EndpointType_ENDPOINT_TYPE_POD {
			epPod := &v1alpha1.PodInfo{
				WorkloadType: metav1.TypeMeta{
					Kind: rec.Endpoint.EP.Kind,
				},
				WorkloadObject: v1alpha1.WorkloadObjectMeta{
					Namespace: rec.Endpoint.EP.Namespace,
					Name:      rec.Endpoint.EP.Name,
				},
				Status: v1alpha1.PodInfoStatus{
					PodIPs: []v1alpha1.PodIP{
						v1alpha1.PodIP{IP: "127.0.0.1"},
					},
				},
			}
			c := endpoint.MustGet()
			c.AddIpPodMap(epPod)
		}
	}
	err := prog.AddRecords(r.records, true)
	require.NoError(t, err)
}

func unloadRecords(r *recordTest, t *testing.T) {
	err := prog.RemoveRecords(r.records)
	require.NoError(t, err)
}

func runCmds(r *recordTest, t *testing.T) {
	for _, cmd := range r.checks {
		switch cmd.check {
		case "curl":
			curlArg := []string{"--max-time", "0.1", "--ipv4", "127.0.0.1:8080"}
			curlCmd := exec.Command("curl", curlArg...)
			err := curlCmd.Run()
			fmt.Printf("curl... %s\n", err)
			if r.deny {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		case "dig":
			digCmd := exec.Command("dig", "localhost")
			err := digCmd.Run()
			fmt.Printf("dig...\n")
			require.NoError(t, err)
		}
	}
}

func deleteOldBpfDir(t *testing.T) {
	path := bpf.MapPrefixPath()
	err := os.RemoveAll(path)
	require.NoError(t, err)
}

func minimalTetragonModel(ctx context.Context, t *testing.T) {
	bpf.ConfigureResourceLimits()
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.CheckOrMountCgroup2()

	option.Config.HubbleLib = "../../../bpf/objs"
	option.Config.BpfDir = bpf.MapPrefixPath()

	enterpriseOption.Config.Layer3CLIEnable = true
	enterpriseOption.Config.EnableTCP = true
	enterpriseOption.Config.EnableUDP = true
	enterpriseOption.Config.EnableBPFDNSParser = true
	enterpriseOption.Config.EnableApplicationModel = true

	obs := observer.NewObserver()
	err := obs.InitSensorManager()
	require.NoError(t, err)
	err = btf.InitCachedBTF(option.Config.HubbleLib, "")
	require.NoError(t, err)
	err = base.LoadDefault(option.Config.BpfDir)
	require.NoError(t, err)
	err = layer3.StartLayer3Progs(ctx)
	require.NoError(t, err)
	err = procevents.GetRunningProcs()
	require.NoError(t, err)
	_, err = model.DefaultNewServer()
	require.NoError(t, err)
}

func TestRecords(t *testing.T) {
	// So far DNS policy are only supported on amd64 but could be extend to arm64 on recent kernels
	if runtime.GOARCH != "amd64" || !kernels.MinKernelVersion("5.15.0") {
		t.Skip()
	}

	// Start an HTTP server serving 128 null bytes on localhost:8080
	server1 := &http.Server{Addr: ":8080", Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(make([]byte, 128))
	})}
	go func() {
		err := server1.ListenAndServe()
		if !errors.Is(err, http.ErrServerClosed) {
			panic(err) // can't call t.Fatal from another goroutine
		}
	}()
	defer server1.Close()

	// Start an HTTP server serving 128 null bytes on localhost:8081
	server2 := &http.Server{Addr: ":8081", Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(make([]byte, 128))
	})}
	go func() {
		err := server2.ListenAndServe()
		if !errors.Is(err, http.ErrServerClosed) {
			panic(err) // can't call t.Fatal from another goroutine
		}
	}()
	defer server2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), sensors.ConfigDefaults.CmdWaitTime)
	defer cancel()

	minimalTetragonModel(ctx, t)
	defer func() {
		observer.RemoveSensors(ctx)
		deleteOldBpfDir(t)
		cgroup.DetachTetragonCgroups(true, true)
	}()

	curlArg := []string{"--max-time", "0.1", "--ipv4", "127.0.0.1:8080"}

	// Check that curl to the domain works
	// Note: wanted to use the Go HTTP request directly but the issue is
	// that the socket is reused between this test and the one after
	// tetragon started
	curlCmd := exec.Command("curl", curlArg...)
	err := curlCmd.Run()
	require.NoError(t, err)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loadRecords(&test, t)
			runCmds(&test, t)
			unloadRecords(&test, t)

			// Check unload provides clean state
			curlCmd := exec.Command("curl", curlArg...)
			err := curlCmd.Run()
			require.NoError(t, err)
		})
	}
}
