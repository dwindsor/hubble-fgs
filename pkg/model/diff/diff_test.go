package diff

import (
	"testing"

	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
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

	diff := StatsDiff(a, b)
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
				Kind:      appModelV1.WorkloadKind_WORKLOAD_KIND_POD,
			},
		},
		Port: 80,
	}
}

func conns() []*appModelV1.ApplicationConnection {
	a := make([]*appModelV1.ApplicationConnection, 2)

	a[0] = &appModelV1.ApplicationConnection{
		Destination: destA(),
		Stats:       connStatsA(),
	}
	a[1] = &appModelV1.ApplicationConnection{
		Destination: destB(),
		Stats:       connStatsB(),
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
	})

	d, err := ConnectionDiff(a, b)
	require.NoError(t, err)

	assert.Equal(t, 2, len(d))
	assert.Equal(t, uint64(1), d[0].Stats.TxBytes)
	assert.Equal(t, uint64(2), d[0].Stats.RxBytes)
	assert.Equal(t, uint64(1), d[0].Stats.DefaultDropBytes)
	assert.Equal(t, uint64(2), d[0].Stats.DefaultAllowBytes)

	assert.Equal(t, uint64(10), d[1].Stats.TxBytes)
	assert.Equal(t, uint64(20), d[1].Stats.RxBytes)
	assert.Equal(t, uint64(15), d[1].Stats.DefaultDropBytes)
	assert.Equal(t, uint64(25), d[1].Stats.DefaultAllowBytes)
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

	d, err := ProcessDiff(aSet, bSet)

	assert.NoError(t, err)
	assert.Equal(t, 1, len(d))
}

func TestProcessConnectDiff(t *testing.T) {
	aSet := psGroup()
	bSet := psGroup()

	a := conns()
	b := conns()

	aSet[1].Connections = a
	bSet[1].Connections = b
	bSet[1].Connections[0].Stats.TxBytes = 1

	dSet, err := ProcessDiff(aSet, bSet)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(dSet))
	assert.Equal(t, 1, len(dSet[0].Connections))
	assert.Equal(t, uint64(9), dSet[0].Connections[0].Stats.TxBytes)
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
		Kind:      appModelV1.WorkloadKind_WORKLOAD_KIND_POD,
		Processes: ps0,
	}

	a[1] = &appModelV1.ApplicationWorkload{
		Name:      "workload1",
		Kind:      appModelV1.WorkloadKind_WORKLOAD_KIND_POD,
		Processes: ps1,
	}
	return a
}

func TestWorkloadEqual(t *testing.T) {
	aSet := workloads()
	bSet := workloads()
	dSet, err := WorkloadDiff(aSet, bSet)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(dSet))
}

func TestWorkloadDiff(t *testing.T) {
	aSet := workloads()
	bSet := workloads()

	bSet[0].Processes[1].Connections[0].Stats.TxBytes = 1

	dSet, err := WorkloadDiff(aSet, bSet)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(dSet))
	assert.Equal(t, 1, len(dSet[0].Processes))
	assert.Equal(t, 1, len(dSet[0].Processes[0].Connections))
	assert.Equal(t, uint64(9), dSet[0].Processes[0].Connections[0].Stats.TxBytes)
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

	d, err := ApplicationModelDiff(aModel, bModel)
	assert.NoError(t, err)
	assert.Nil(t, d)
}

func TestApplicationModelDiff(t *testing.T) {
	aModel := appModel()
	bModel := appModel()
	bModel.Namespaces[0].Workloads[0].Processes[1].Connections[0].Stats.TxBytes = 1

	d, err := ApplicationModelDiff(aModel, bModel)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(d.Namespaces))
	assert.Equal(t, 1, len(d.Namespaces[0].Workloads))
	assert.Equal(t, 1, len(d.Namespaces[0].Workloads[0].Processes))
	assert.Equal(t, 1, len(d.Namespaces[0].Workloads[0].Processes[0].Connections))
	assert.Equal(t, uint64(9), d.Namespaces[0].Workloads[0].Processes[0].Connections[0].Stats.TxBytes)
}

func TestToNetworkFlat(t *testing.T) {
	aModel := appModel()
	bModel := appModel()
	bModel.Namespaces[0].Workloads[0].Processes[1].Connections[0].Stats.TxBytes = 1
	bModel.Namespaces[1].Workloads[1].Processes[1].Connections[1].Stats.RxBytes = 1

	d, err := ApplicationModelDiff(aModel, bModel)
	assert.NoError(t, err)

	f, err := ApplicationModelToNetworkFlat(d)
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
	assert.Equal(t, appModelV1.ApplicationModelDestinationType_APPLICATION_MODEL_DESTINATION_TYPE_CIDR, f[0].DestinationType)
	assert.Equal(t, appModelV1.ApplicationModelDestinationType_APPLICATION_MODEL_DESTINATION_TYPE_DNS, f[1].DestinationType)
	assert.Equal(t, uint32(80), f[0].DestinationPort)
	assert.Equal(t, uint32(80), f[1].DestinationPort)
	assert.Equal(t, uint64(9), f[0].TxBytes)
	assert.Equal(t, uint64(0), f[1].TxBytes)
	assert.Equal(t, uint64(0), f[0].RxBytes)
	assert.Equal(t, uint64(1), f[1].RxBytes)
}

func TestToNetworkFlatHost(t *testing.T) {
	aHost := hostModel()
	bHost := hostModel()
	bHost.Processes[1].Connections[0].Stats.TxBytes = 1

	aModel := &appModelV1.ApplicationModel{
		Namespaces: []*appModelV1.ApplicationNamespace{},
		Host:       aHost,
	}
	bModel := &appModelV1.ApplicationModel{
		Namespaces: []*appModelV1.ApplicationNamespace{},
		Host:       bHost,
	}

	d, err := ApplicationModelDiff(aModel, bModel)
	assert.NoError(t, err)

	f, err := ApplicationModelToNetworkFlat(d)
	assert.NoError(t, err)
	assert.Equal(t, "", f[0].KubernetesNamespace)
	assert.Equal(t, "", f[0].KubernetesWorkloadName)
	assert.Equal(t, "ci", f[0].ProcessName)
	assert.Equal(t, "makesThingsWork", f[0].ProcessArguments)
	assert.Equal(t, "10.0.0.1", f[0].DestinationName)
	assert.Equal(t, appModelV1.ApplicationModelDestinationType_APPLICATION_MODEL_DESTINATION_TYPE_CIDR, f[0].DestinationType)
	assert.Equal(t, uint32(80), f[0].DestinationPort)
	assert.Equal(t, uint64(9), f[0].TxBytes)
	assert.Equal(t, uint64(0), f[0].RxBytes)
}

func Test_getDestination(t *testing.T) {
	dest := appModelV1.Destination{
		Type: &appModelV1.Destination_Workload{
			Workload: &appModelV1.DestinationWorkload{
				Name:      "kubernetes",
				Namespace: "default",
				Kind:      appModelV1.WorkloadKind_WORKLOAD_KIND_SERVICE,
			},
		},
		Port: 1234,
	}
	name, namespace, workloadName, workloadKind := getDestination(&dest)
	assert.Equal(t, "default:WORKLOAD_KIND_SERVICE:kubernetes", name)
	assert.Equal(t, dest.GetWorkload().GetNamespace(), namespace)
	assert.Equal(t, dest.GetWorkload().GetName(), workloadName)
	assert.Equal(t, dest.GetWorkload().GetKind(), workloadKind)
}
