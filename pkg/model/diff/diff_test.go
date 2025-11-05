package diff

import (
	"context"
	"testing"

	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	common "github.com/isovalent/ipa/common/k8s/type/v1alpha"
	graphV1 "github.com/isovalent/ipa/graph/v1alpha"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func connStatsA() *appModelV1.ConnectionStats {
	return &appModelV1.ConnectionStats{
		TxBytes:           10,
		RxBytes:           20,
		TxDrops:           30,
		TxQuota:           40,
		TxQuotaUsage:      1,
		DefaultDropBytes:  15,
		DefaultAllowBytes: 25,
	}
}

func connStatsB() *appModelV1.ConnectionStats {
	return &appModelV1.ConnectionStats{
		TxBytes:           1,
		RxBytes:           2,
		TxDrops:           3,
		TxQuota:           4,
		TxQuotaUsage:      1,
		DefaultDropBytes:  1,
		DefaultAllowBytes: 2,
	}
}

func connStatsDiff() *appModelV1.ConnectionStats {
	return &appModelV1.ConnectionStats{
		TxBytes:           9,
		RxBytes:           18,
		TxDrops:           27,
		TxQuota:           40,
		TxQuotaUsage:      1,
		DefaultDropBytes:  14,
		DefaultAllowBytes: 23,
	}
}

func connStatsEqual(t *testing.T, a, b *appModelV1.ConnectionStats) {
	assert.Equal(t, a.TxBytes, b.TxBytes)
	assert.Equal(t, a.RxBytes, b.RxBytes)
	assert.Equal(t, a.TxDrops, b.TxDrops)
	assert.Equal(t, a.TxQuota, b.TxQuota)
	assert.Equal(t, a.TxQuotaUsage, b.TxQuotaUsage)
	assert.Equal(t, a.DefaultDropBytes, b.DefaultDropBytes)
	assert.Equal(t, a.DefaultAllowBytes, b.DefaultAllowBytes)
}

func TestStatsDiff(t *testing.T) {
	a := connStatsA()
	b := connStatsB()
	abResult := connStatsDiff()

	diff, err := StatsDiff(a, b)
	assert.NoError(t, err)
	connStatsEqual(t, diff, abResult)
}

func destA() *appModelV1.Destination {
	return &appModelV1.Destination{
		Type: &appModelV1.Destination_Ip{
			Ip: &appModelV1.DestinationIP{
				Ip: "10.0.0.1",
			},
		},
		Port: 80,
	}
}

func destB() *appModelV1.Destination {
	return &appModelV1.Destination{
		Type: &appModelV1.Destination_Dns{
			Dns: &appModelV1.DestinationDns{
				DestinationNames: []string{"ebpf.io", "isovalent.io", "cisco.com"},
			},
		},
		Port: 80,
	}
}

func destC() *appModelV1.Destination {
	return &appModelV1.Destination{
		Type: &appModelV1.Destination_Workload{
			Workload: &appModelV1.DestinationWorkload{
				Name:      "foo",
				Namespace: "fooNS",
				Kind:      common.WorkloadKind_WORKLOAD_KIND_POD,
			},
		},
		Port: 80,
	}
}

func policy() *appModelV1.NetworkPolicy {
	return &appModelV1.NetworkPolicy{
		PolicyName: "aTestPolicy",
	}
}

func conns() []*appModelV1.ApplicationConnection {
	a := make([]*appModelV1.ApplicationConnection, 2)

	a[0] = &appModelV1.ApplicationConnection{
		Destination: destA(),
		Stats:       connStatsA(),
		Policy:      policy(),
	}
	a[1] = &appModelV1.ApplicationConnection{
		Destination: destB(),
		Stats:       connStatsB(),
		Policy:      policy(),
	}
	return a
}

func TestConnectionStatsDiff(t *testing.T) {
	a := conns()
	b := conns()

	a[0].Stats.TxBytes++
	a[0].Stats.RxBytes += 2
	a[0].Stats.DefaultDropBytes++
	a[0].Stats.DefaultAllowBytes += 2

	a = append(a, &appModelV1.ApplicationConnection{
		Destination: destC(),
		Stats:       connStatsA(),
		Policy:      policy(),
	})

	d, err := ConnectionDiff(a, b)
	require.NoError(t, err)

	assert.Equal(t, 2, len(d))
	assert.Equal(t, uint64(1), d[0].Stats.TxBytes)
	assert.Equal(t, uint64(2), d[0].Stats.RxBytes)
	assert.Equal(t, uint64(1), d[0].Stats.DefaultDropBytes)
	assert.Equal(t, uint64(2), d[0].Stats.DefaultAllowBytes)
	assert.Equal(t, "aTestPolicy", d[0].Policy.PolicyName)

	assert.Equal(t, uint64(10), d[1].Stats.TxBytes)
	assert.Equal(t, uint64(20), d[1].Stats.RxBytes)
	assert.Equal(t, uint64(15), d[1].Stats.DefaultDropBytes)
	assert.Equal(t, uint64(25), d[1].Stats.DefaultAllowBytes)
	assert.Equal(t, "aTestPolicy", d[1].Policy.PolicyName)
}

func psGroup() []*appModelV1.ApplicationProcessGroup {
	a := make([]*appModelV1.ApplicationProcessGroup, 2)

	a[0] = &appModelV1.ApplicationProcessGroup{
		Hash:            "0xabcd",
		Name:            "foolishFish",
		Arguments:       "havingFun",
		Children:        []*appModelV1.ApplicationProcessGroup{},
		SyscallInfo:     nil,
		ProcessCount:    1,
		LatestStartTime: nil,
	}

	a[1] = &appModelV1.ApplicationProcessGroup{
		Hash:            "0x1234",
		Name:            "ci",
		Arguments:       "makesThingsWork",
		Children:        []*appModelV1.ApplicationProcessGroup{},
		SyscallInfo:     nil,
		ProcessCount:    1,
		LatestStartTime: nil,
	}
	return a
}

func TestProcessDiff(t *testing.T) {
	aSet := psGroup()
	bSet := psGroup()

	bSet[1].Name = "ciNew"
	bSet[1].Arguments = "NewCIIsBest"

	network, process, err := ProcessDiff(aSet, bSet)

	assert.NoError(t, err)
	assert.Equal(t, 1, len(process))
	assert.Equal(t, 0, len(network))
}

func TestProcessConnectDiff(t *testing.T) {
	aSet := psGroup()
	bSet := psGroup()

	a := conns()
	b := conns()

	aSet[1].Connections = a
	bSet[1].Connections = b
	bSet[1].Connections[0].Stats.TxBytes = 1

	network, process, err := ProcessDiff(aSet, bSet)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(network))
	assert.Equal(t, 1, len(network[0].Connections))
	assert.Equal(t, uint64(9), network[0].Connections[0].Stats.TxBytes)
	assert.Equal(t, 0, len(process))
}

func TestProcessNetworkConnectDiff(t *testing.T) {
	aSet := psGroup()
	bSet := psGroup()

	a := conns()
	b := conns()

	aSet[1].Connections = a
	aSet[1].Connections[0].Stats.TxBytes = 2
	aSet[1].Connections[1].Stats.TxBytes = 3
	aSet[1].Arguments = "NewCIIsBest"
	bSet[1].Connections = b

	network, process, err := ProcessDiff(aSet, bSet)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(network))
	assert.Equal(t, 2, len(network[0].Connections))
	assert.Equal(t, uint64(2), network[0].Connections[0].Stats.TxBytes)
	assert.Equal(t, uint64(3), network[0].Connections[1].Stats.TxBytes)
	assert.Equal(t, 1, len(process))
	assert.Equal(t, "ci", process[0].Name)
	assert.Equal(t, "NewCIIsBest", process[0].Arguments)
}

func workloads() []*appModelV1.ApplicationWorkload {
	a := make([]*appModelV1.ApplicationWorkload, 2)

	ps0 := psGroup()
	ps1 := psGroup()
	psConns0 := conns()
	psConns1 := conns()

	ps0[1].Connections = psConns0
	ps1[1].Connections = psConns1

	a[0] = &appModelV1.ApplicationWorkload{
		Name:      "workload2",
		Kind:      common.WorkloadKind_WORKLOAD_KIND_POD,
		Processes: ps0,
	}

	a[1] = &appModelV1.ApplicationWorkload{
		Name:      "workload1",
		Kind:      common.WorkloadKind_WORKLOAD_KIND_POD,
		Processes: ps1,
	}
	return a
}

func TestWorkloadEqual(t *testing.T) {
	aSet := workloads()
	bSet := workloads()
	netSet, procSet, err := WorkloadDiff(aSet, bSet)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(procSet))
	assert.Equal(t, 0, len(netSet))
}

func TestWorkloadDiff(t *testing.T) {
	aSet := workloads()
	bSet := workloads()

	bSet[0].Processes[1].Connections[0].Stats.TxBytes = 1

	network, process, err := WorkloadDiff(aSet, bSet)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(process))
	assert.Equal(t, 1, len(network))
	assert.Equal(t, 1, len(network[0].Processes))
	assert.Equal(t, 1, len(network[0].Processes[0].Connections))
	assert.Equal(t, uint64(9), network[0].Processes[0].Connections[0].Stats.TxBytes)
}

func TestWorkloadNetProcDiff(t *testing.T) {
	aSet := workloads()
	bSet := workloads()

	bSet[1].Processes[1].Connections[0].Stats.TxBytes = 1
	aSet[0].Processes[1].Arguments = "changes"

	network, process, err := WorkloadDiff(aSet, bSet)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(process))
	assert.Equal(t, 1, len(process[0].Processes))
	assert.Equal(t, 2, len(process[0].Processes[0].Connections))
	assert.Equal(t, "ci", process[0].Processes[0].Name)
	assert.Equal(t, "changes", process[0].Processes[0].Arguments)

	assert.Equal(t, 2, len(network))

	assert.Equal(t, 1, len(network[0].Processes))
	assert.Equal(t, 2, len(network[0].Processes[0].Connections))
	assert.Equal(t, uint64(10), network[0].Processes[0].Connections[0].Stats.TxBytes)
	assert.Equal(t, uint64(1), network[0].Processes[0].Connections[1].Stats.TxBytes)

	assert.Equal(t, 1, len(network[1].Processes))
	assert.Equal(t, 1, len(network[1].Processes[0].Connections))
	assert.Equal(t, uint64(9), network[1].Processes[0].Connections[0].Stats.TxBytes)
}

func TestWorkloadNameDiff(t *testing.T) {
	aSet := workloads()
	bSet := workloads()

	aSet[0].Name = "wl-changes"

	network, process, err := WorkloadDiff(aSet, bSet)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(process))
	assert.Equal(t, 1, len(network))

	// Processes
	assert.Equal(t, 2, len(process[0].Processes))
	assert.Equal(t, 1, len(network[0].Processes))
	// Assert Process is copied through correctly.
	assert.Equal(t, "foolishFish", process[0].Processes[0].Name)
	assert.Equal(t, "havingFun", process[0].Processes[0].Arguments)
	assert.Equal(t, "ci", process[0].Processes[1].Name)
	assert.Equal(t, "makesThingsWork", process[0].Processes[1].Arguments)
	// Assert Network is copied through correctly
	assert.Equal(t, "ci", network[0].Processes[0].Name)
	assert.Equal(t, "makesThingsWork", network[0].Processes[0].Arguments)
	assert.Equal(t, 2, len(network[0].Processes[0].Connections))
	assert.Equal(t, uint64(10), network[0].Processes[0].Connections[0].Stats.TxBytes)
	assert.Equal(t, uint64(1), network[0].Processes[0].Connections[1].Stats.TxBytes)
}

func hostModel() *appModelV1.ApplicationHost {
	aSet := psGroup()

	a := conns()
	aSet[1].Connections = a

	return &appModelV1.ApplicationHost{
		Processes: aSet,
	}
}

func appModel() *appModelV1.ApplicationModel {
	wl1 := workloads()
	wl2 := workloads()

	ns1 := &appModelV1.ApplicationNamespace{
		Name:      "ns1",
		Workloads: wl1,
	}
	ns2 := &appModelV1.ApplicationNamespace{
		Name:      "ns2",
		Workloads: wl2,
	}
	ns := []*appModelV1.ApplicationNamespace{ns1, ns2}

	model := &appModelV1.ApplicationModel{
		Namespaces: ns,
	}

	return model
}

func TestApplicationModelEqual(t *testing.T) {
	aModel := appModel()
	bModel := appModel()

	_, d, err := ApplicationModelDiff(aModel, bModel)
	assert.NoError(t, err)
	assert.Nil(t, d)
}

func TestApplicationModelDiff(t *testing.T) {
	aModel := appModel()
	bModel := appModel()
	bModel.Namespaces[0].Workloads[0].Processes[1].Connections[0].Stats.TxBytes = 1

	network, process, err := ApplicationModelDiff(aModel, bModel)
	assert.NoError(t, err)
	assert.Nil(t, process)
	assert.Equal(t, 1, len(network.Namespaces))
	assert.Equal(t, 1, len(network.Namespaces[0].Workloads))
	assert.Equal(t, 1, len(network.Namespaces[0].Workloads[0].Processes))
	assert.Equal(t, 1, len(network.Namespaces[0].Workloads[0].Processes[0].Connections))
	assert.Equal(t, uint64(9), network.Namespaces[0].Workloads[0].Processes[0].Connections[0].Stats.TxBytes)
}

func TestApplicationModelProcNetDiff(t *testing.T) {
	aModel := appModel()
	bModel := appModel()
	bModel.Namespaces[0].Workloads[0].Processes[1].Connections[0].Stats.TxBytes = 1
	aModel.Namespaces[1].Workloads[1].Processes[1].Arguments = "changes"

	network, process, err := ApplicationModelDiff(aModel, bModel)
	assert.NoError(t, err)
	assert.NotNil(t, network)
	assert.NotNil(t, process)

	assert.Equal(t, 1, len(process.Namespaces))
	assert.Equal(t, 2, len(network.Namespaces))

	// TxBytes inc adds a single process Connection to network
	assert.Equal(t, 1, len(network.Namespaces[0].Workloads))
	assert.Equal(t, 1, len(network.Namespaces[0].Workloads[0].Processes))
	assert.Equal(t, 1, len(network.Namespaces[0].Workloads[0].Processes[0].Connections))
	assert.Equal(t, uint64(9), network.Namespaces[0].Workloads[0].Processes[0].Connections[0].Stats.TxBytes)
	// Args change adds two new process Connections to network
	assert.Equal(t, 1, len(network.Namespaces[1].Workloads))
	assert.Equal(t, 1, len(network.Namespaces[1].Workloads[0].Processes))
	assert.Equal(t, 2, len(network.Namespaces[1].Workloads[0].Processes[0].Connections))
	assert.Equal(t, uint64(10), network.Namespaces[1].Workloads[0].Processes[0].Connections[0].Stats.TxBytes)
	assert.Equal(t, uint64(1), network.Namespaces[1].Workloads[0].Processes[0].Connections[1].Stats.TxBytes)
	// Arguments impact to process
	assert.Equal(t, 1, len(process.Namespaces[0].Workloads))
	assert.Equal(t, 1, len(process.Namespaces[0].Workloads[0].Processes))
	assert.Equal(t, "ci", process.Namespaces[0].Workloads[0].Processes[0].Name)
	assert.Equal(t, "changes", process.Namespaces[0].Workloads[0].Processes[0].Arguments)
}

func TestApplicationModelNSDiff(t *testing.T) {
	aModel := appModel()
	bModel := appModel()

	aModel.Namespaces[0].Name = "new-ns"

	network, process, err := ApplicationModelDiff(aModel, bModel)
	assert.NoError(t, err)
	assert.NotNil(t, network)
	assert.NotNil(t, process)

	assert.Equal(t, 1, len(process.Namespaces))
	assert.Equal(t, 1, len(network.Namespaces))

	assert.Equal(t, 2, len(network.Namespaces[0].Workloads))
	assert.Equal(t, 1, len(network.Namespaces[0].Workloads[0].Processes))
	assert.Equal(t, 1, len(network.Namespaces[0].Workloads[1].Processes))
	assert.Equal(t, 2, len(network.Namespaces[0].Workloads[0].Processes[0].Connections))
	assert.Equal(t, 2, len(network.Namespaces[0].Workloads[1].Processes[0].Connections))
	assert.Equal(t, uint64(10), network.Namespaces[0].Workloads[0].Processes[0].Connections[0].Stats.TxBytes)
	assert.Equal(t, uint64(1), network.Namespaces[0].Workloads[0].Processes[0].Connections[1].Stats.TxBytes)

	assert.Equal(t, 2, len(process.Namespaces[0].Workloads))
	assert.Equal(t, 2, len(process.Namespaces[0].Workloads[0].Processes))
	assert.Equal(t, 2, len(process.Namespaces[0].Workloads[1].Processes))
	assert.Equal(t, 0, len(process.Namespaces[0].Workloads[0].Processes[0].Connections))
	assert.Equal(t, 2, len(process.Namespaces[0].Workloads[0].Processes[1].Connections))
	assert.Equal(t, "new-ns", network.Namespaces[0].Name)
}

func TestToNetworkFlat(t *testing.T) {
	ctx := context.Background()

	aModel := appModel()
	aModel.Id = "u-u-i-d"
	bModel := appModel()
	bModel.Namespaces[0].Workloads[0].Processes[1].Connections[0].Stats.TxBytes = 1
	bModel.Namespaces[1].Workloads[1].Processes[1].Connections[1].Stats.RxBytes = 1

	network, process, err := ApplicationModelDiff(aModel, bModel)
	assert.NoError(t, err)

	assert.Nil(t, process)
	assert.Equal(t, 2, len(network.Namespaces))

	f, err := ApplicationModelToNetworkFlat(ctx, network)
	assert.NoError(t, err)
	assert.Equal(t, "ns1", f[0].KubernetesNamespace)
	assert.Equal(t, "ns2", f[1].KubernetesNamespace)
	assert.Equal(t, "workload2", f[0].KubernetesWorkloadName)
	assert.Equal(t, "workload1", f[1].KubernetesWorkloadName)
	assert.Equal(t, "ci", f[0].ProcessName)
	assert.Equal(t, "ci", f[1].ProcessName)
	assert.Equal(t, "makesThingsWork", f[0].ProcessArguments)
	assert.Equal(t, "makesThingsWork", f[1].ProcessArguments)
	assert.Equal(t, "10.0.0.1", f[0].DestinationName)
	assert.Equal(t, "cisco.com", f[1].DestinationName)
	assert.Equal(t, appModelV1.DestinationType_DESTINATION_TYPE_CIDR, f[0].DestinationType)
	assert.Equal(t, appModelV1.DestinationType_DESTINATION_TYPE_DNS, f[1].DestinationType)
	assert.Equal(t, uint32(80), f[0].DestinationPort)
	assert.Equal(t, uint32(80), f[1].DestinationPort)
	assert.Equal(t, uint64(9), f[0].TxBytes)
	assert.Equal(t, uint64(0), f[1].TxBytes)
	assert.Equal(t, uint64(0), f[0].RxBytes)
	assert.Equal(t, uint64(1), f[1].RxBytes)
	assert.Equal(t, aModel.Id, f[0].ApplicationModelId)
	assert.Equal(t, aModel.Id, f[1].ApplicationModelId)
}

func TestToNetworkFlatHost(t *testing.T) {
	ctx := context.Background()

	aHost := hostModel()
	bHost := hostModel()
	bHost.Processes[1].Connections[0].Stats.TxBytes = 1

	aModel := &appModelV1.ApplicationModel{
		Namespaces: []*appModelV1.ApplicationNamespace{},
		Host:       aHost,
		Id:         "u-u-i-d",
	}
	bModel := &appModelV1.ApplicationModel{
		Namespaces: []*appModelV1.ApplicationNamespace{},
		Host:       bHost,
	}

	network, process, err := ApplicationModelDiff(aModel, bModel)
	assert.NoError(t, err)
	assert.Nil(t, process)

	f, err := ApplicationModelToNetworkFlat(ctx, network)
	assert.NoError(t, err)
	assert.Equal(t, "", f[0].KubernetesNamespace)
	assert.Equal(t, "", f[0].KubernetesWorkloadName)
	assert.Equal(t, "ci", f[0].ProcessName)
	assert.Equal(t, "makesThingsWork", f[0].ProcessArguments)
	assert.Equal(t, "10.0.0.1", f[0].DestinationName)
	assert.Equal(t, appModelV1.DestinationType_DESTINATION_TYPE_CIDR, f[0].DestinationType)
	assert.Equal(t, uint32(80), f[0].DestinationPort)
	assert.Equal(t, uint64(9), f[0].TxBytes)
	assert.Equal(t, uint64(0), f[0].RxBytes)
	assert.Equal(t, aModel.Id, f[0].ApplicationModelId)
}

// This is broken after IPA upgrades the UNSPECIFIED should be a service.
func Test_getDestination(t *testing.T) {
	dest := appModelV1.Destination{
		Type: &appModelV1.Destination_Workload{
			Workload: &appModelV1.DestinationWorkload{
				Name:      "kubernetes",
				Namespace: "default",
				Kind:      common.WorkloadKind_WORKLOAD_KIND_UNSPECIFIED,
			},
		},
		Port: 1234,
	}
	name, namespace, workloadName, workloadKind := getDestination(&dest)
	assert.Equal(t, "default:WORKLOAD_KIND_UNSPECIFIED:kubernetes", name)
	assert.Equal(t, dest.GetWorkload().GetNamespace(), namespace)
	assert.Equal(t, dest.GetWorkload().GetName(), workloadName)
	assert.Equal(t, dest.GetWorkload().GetKind(), workloadKind)
}

func TestTelemetryToConnection(t *testing.T) {
	tests := []struct {
		name      string
		telemetry *appModelV1.NetworkConnectTelemetry
		expected  *graphV1.Connection
	}{
		{
			name: "DNS destination type",
			telemetry: &appModelV1.NetworkConnectTelemetry{
				EventType:              appModelV1.TelemetryType_TELEMETRY_TYPE_NETWORK_CONNECT,
				ClusterName:            "my-cluster",
				NodeName:               "my-node",
				KubernetesNamespace:    "tetragon",
				KubernetesWorkloadKind: common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
				KubernetesWorkloadName: "tetragon-grafana",
				DestinationName:        "grafana.com",
				DestinationType:        appModelV1.DestinationType_DESTINATION_TYPE_DNS,
				DestinationPort:        443,
				TxBytes:                1234,
				ApplicationModelId:     "u-u-i-d",
			},
			expected: &graphV1.Connection{
				Source: &graphV1.Vertex{
					Family: &graphV1.Vertex_Kubernetes{
						Kubernetes: &graphV1.VertexFamilyKubernetes{
							ResourceName:         "tetragon-grafana",
							ClusterName:          "my-cluster",
							Namespace:            "tetragon",
							NodeName:             "my-node",
							WorkloadKind:         common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
							ApplicationModelUuid: "u-u-i-d",
						},
					},
				},
				Destination: &graphV1.Vertex{
					Family: &graphV1.Vertex_WorldEntity{
						WorldEntity: &graphV1.VertexFamilyWorldEntity{
							DnsName: "grafana.com",
							Port:    443,
						},
					},
				},
				Links: []*graphV1.Edge{
					{
						Type: &graphV1.Edge_NetworkTelemetry{
							NetworkTelemetry: &graphV1.EdgeTypeNetworkTelemetry{
								NetworkTransmitBytesTotal: 1234,
							},
						},
					},
				},
			},
		},
		{
			name: "CIDR destination type",
			telemetry: &appModelV1.NetworkConnectTelemetry{
				EventType:              appModelV1.TelemetryType_TELEMETRY_TYPE_NETWORK_CONNECT,
				ClusterName:            "my-cluster",
				NodeName:               "my-node",
				KubernetesNamespace:    "tetragon",
				KubernetesWorkloadKind: common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
				KubernetesWorkloadName: "tetragon-grafana",
				DestinationName:        "192.168.0.2",
				DestinationType:        appModelV1.DestinationType_DESTINATION_TYPE_CIDR,
				DestinationPort:        443,
				TxBytes:                1234,
				ApplicationModelId:     "u-u-i-d",
			},
			expected: &graphV1.Connection{
				Source: &graphV1.Vertex{
					Family: &graphV1.Vertex_Kubernetes{
						Kubernetes: &graphV1.VertexFamilyKubernetes{
							ResourceName:         "tetragon-grafana",
							ClusterName:          "my-cluster",
							Namespace:            "tetragon",
							NodeName:             "my-node",
							WorkloadKind:         common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
							ApplicationModelUuid: "u-u-i-d",
						},
					},
				},
				Destination: &graphV1.Vertex{
					Family: &graphV1.Vertex_WorldEntity{
						WorldEntity: &graphV1.VertexFamilyWorldEntity{
							DnsName: "192.168.0.2",
							Port:    443,
						},
					},
				},
				Links: []*graphV1.Edge{
					{
						Type: &graphV1.Edge_NetworkTelemetry{
							NetworkTelemetry: &graphV1.EdgeTypeNetworkTelemetry{
								NetworkTransmitBytesTotal: 1234,
							},
						},
					},
				},
			},
		},
		{
			name: "k8s destination type",
			telemetry: &appModelV1.NetworkConnectTelemetry{
				EventType:                         appModelV1.TelemetryType_TELEMETRY_TYPE_NETWORK_CONNECT,
				ClusterName:                       "my-cluster",
				NodeName:                          "my-node",
				KubernetesNamespace:               "tetragon",
				KubernetesWorkloadKind:            common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
				KubernetesWorkloadName:            "tetragon-grafana",
				DestinationName:                   "192.168.0.2",
				DestinationType:                   appModelV1.DestinationType_DESTINATION_TYPE_KUBERNETES,
				DestinationKubernetesResourceKind: common.ResourceKind_RESOURCE_KIND_SERVICE,
				DestinationKubernetesNamespace:    "another-namespace",
				DestinationKubernetesResourceName: "another-service",
				DestinationKubernetesServiceKind:  common.ServiceKind_SERVICE_KIND_CLUSTER_IP,
				DestinationKubernetesWorkloadKind: common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
				DestinationPort:                   443,
				TxBytes:                           1234,
				ApplicationModelId:                "u-u-i-d",
			},
			expected: &graphV1.Connection{
				Source: &graphV1.Vertex{
					Family: &graphV1.Vertex_Kubernetes{
						Kubernetes: &graphV1.VertexFamilyKubernetes{
							ResourceName:         "tetragon-grafana",
							ClusterName:          "my-cluster",
							Namespace:            "tetragon",
							NodeName:             "my-node",
							WorkloadKind:         common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
							ApplicationModelUuid: "u-u-i-d",
						},
					},
				},
				Destination: &graphV1.Vertex{
					Family: &graphV1.Vertex_Kubernetes{
						Kubernetes: &graphV1.VertexFamilyKubernetes{
							ResourceKind: common.ResourceKind_RESOURCE_KIND_SERVICE,
							ResourceName: "another-service",
							ClusterName:  "my-cluster",
							Namespace:    "another-namespace",
							ServiceKind:  common.ServiceKind_SERVICE_KIND_CLUSTER_IP,
							WorkloadKind: common.WorkloadKind_WORKLOAD_KIND_DEPLOYMENT,
							Port:         443,
						},
					},
				},
				Links: []*graphV1.Edge{
					{
						Type: &graphV1.Edge_NetworkTelemetry{
							NetworkTelemetry: &graphV1.EdgeTypeNetworkTelemetry{
								NetworkTransmitBytesTotal: 1234,
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connection := TelemetryToConnection(tt.telemetry)
			assert.EqualExportedValues(t, tt.expected, connection)
		})
	}
}
