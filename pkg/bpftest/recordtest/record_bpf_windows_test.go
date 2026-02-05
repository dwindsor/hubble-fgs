// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package recordbpftest

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/bpftest"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/datapath"
	"github.com/isovalent/hubble-fgs/pkg/model/record"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/isovalent/hubble-fgs/pkg/testutils"

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
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicy1",
			RuleName:   "testRule1",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				CIDR: netip.MustParsePrefix("127.0.0.1/32"),
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyDeny,
		},
	}
	ipLo1AllowPolicy = &record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicyAllow1",
			RuleName:   "testRuleAllow1",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				CIDR: netip.MustParsePrefix("127.0.0.1/32"),
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyAllow,
		},
	}
	ipLo2Policy = &record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicy2",
			RuleName:   "testRule2",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				CIDR: netip.MustParsePrefix("127.0.0.2/32"),
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyDeny,
		},
	}
	ipLo2AllowPolicy = &record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicyAllow2",
			RuleName:   "testRuleAllow2",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				CIDR: netip.MustParsePrefix("127.0.0.2/32"),
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyAllow,
		},
	}
	ipLo3Policy = &record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicy3",
			RuleName:   "testRule3",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				CIDR: netip.MustParsePrefix("127.0.0.0/24"),
			},
			Port: 0,
		},
		Action: &record.DatapathAction{
			Action: record.PolicyDeny,
		},
	}
	ipLo3AllowPolicy = &record.DatapathRecord{
		PolicyUID: types.TetragonPolicyUniqueID{
			PolicyName: "testPolicyAllow3",
			RuleName:   "testRuleAllow3",
		},
		Src: wildcardSrc,
		Endpoint: record.DatapathEndpoint{
			EP: &endpoint.Endpoint{
				Type: tetragon.EndpointType_ENDPOINT_TYPE_CIDR,
				CIDR: netip.MustParsePrefix("127.0.0.0/24"),
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
	curl = []recordCheck{recordCheck{check: "curl"}}
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
			curlArg := []string{"127.0.0.1:8080"}
			curlCmd := exec.Command("curl", curlArg...)
			err := curlCmd.Run()
			t.Logf("curl... %s", err)
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

func TestRecords(t *testing.T) {
	// So far DNS policy are only supported on amd64 but could be extend to arm64 on recent kernels
	if runtime.GOARCH != "amd64" {
		t.Skip()
	}

	testutils.StartSimpleHTTPServer(t, ":8080")
	testutils.StartSimpleHTTPServer(t, ":8081")

	ctx, cancel := context.WithTimeout(context.Background(), sensors.ConfigDefaults.CmdWaitTime)
	defer cancel()

	bpftest.StartMinimalTetragonModel(ctx, t)

	curlArg := []string{"127.0.0.1:8080"}

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
