//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package network

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/api/processapi"
	"github.com/isovalent/hubble-fgs/pkg/defaults"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
	"github.com/vishvananda/netlink"

	"github.com/containernetworking/plugins/pkg/ns"
)

var (
	NetworkStatInterval = time.Duration(60 * time.Second)
	sandboxToContainer  = make(map[string]string)
)

func emitInterfaceEvent(attrs *netlink.LinkAttrs, netns string, netnsFilePath string) {
	unix := api.MsgInterfaceEventUnix{
		Common: processapi.MsgCommon{
			Op:    ops.MSG_OP_INTERFACE_STATS,
			Size:  1,
			Ktime: 0,
		},
		Iface: api.MsgInterface{
			Index:         attrs.Index,
			Name:          attrs.Name,
			Netns:         netns,
			ContainerName: getContainerName(netnsFilePath),
		},
		Stats: api.MsgInterfaceStats{
			BytesSent:       attrs.Statistics.TxBytes,
			BytesReceived:   attrs.Statistics.RxBytes,
			PacketsSent:     attrs.Statistics.TxPackets,
			PacketsReceived: attrs.Statistics.RxPackets,
			TxErrors:        attrs.Statistics.TxErrors,
			RxErrors:        attrs.Statistics.RxErrors,
			TxDrops:         attrs.Statistics.TxDropped,
			RxDrops:         attrs.Statistics.RxDropped,
		},
	}
	observer.AllListeners(&unix)
	return
}

func runNetworkCB() {
	links, err := netlink.LinkList()
	if err != nil {
		logger.GetLogger().WithError(err).Infof("Link list failed")
	} else {
		for _, l := range links {
			emitInterfaceEvent(l.Attrs(), "", "")
		}
	}

	nsDir, err := ioutil.ReadDir(defaults.NetnsDir)
	if err != nil {
		return
	}

	for fileIndex := range nsDir {
		nsFile := nsDir[fileIndex]
		nsFileName := filepath.Join(defaults.NetnsDir, nsFile.Name())

		netns, err := ns.GetNS(nsFileName)
		if err != nil {
			logger.GetLogger().WithField("pid", os.Getpid()).WithField("file", nsFileName).WithError(err).Infof("GetNS from path failed")
			continue
		}
		defer netns.Close()

		err = netns.Do(func(_ ns.NetNS) error {
			links, err = netlink.LinkList()
			if err != nil {
				logger.GetLogger().WithField("pid", os.Getpid()).WithField("file", nsFileName).WithError(err).Infof("netns LinkList failed")
				return fmt.Errorf("Netlink LinkList() error: %v", err)
			}
			for _, l := range links {
				emitInterfaceEvent(l.Attrs(), nsFile.Name(), nsFileName)
			}
			return nil
		})
	}
}

func networkCB(gcInterval time.Duration) {
	ticker := time.NewTicker(gcInterval)
	go func() {
		for {
			select {
			case <-ticker.C:
				runNetworkCB()
			}
		}
	}()
}

type networkSensor struct {
	name string
}

func (net *networkSensor) LoadProbe(args sensors.LoadProbeArgs) (int, error) {
	return 0, nil
}

func EnableNetworkParser(statInterval uint32) *sensors.Sensor {
	var defaultCBInterval time.Duration

	if statInterval == 0 {
		defaultCBInterval = NetworkStatInterval
	} else {
		defaultCBInterval = time.Duration(time.Duration(statInterval) * time.Second)
	}

	logger.GetLogger().Infof("Enable Interface Statistics")
	err := populateSandboxToContainer()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Interface statistics running without containerID info")
	}
	networkCB(defaultCBInterval)
	return nil
}

func (net *networkSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
	if !spec.Parser.Interface.Enable {
		return nil, nil
	}
	return EnableNetworkParser(spec.Parser.Interface.StatsInterval), nil
}

func init() {
	AddNetwork()
}

func AddNetwork() {
	net := &networkSensor{
		name: "Interface sensor",
	}
	sensors.RegisterProbeType("interface_sensor", net)
	sensors.RegisterTracingSensorsAtInit(net.name, net)
}

func getContainerName(sandboxKey string) string {
	if sandboxKey == "" {
		return ""
	}
	containerName := sandboxToContainer[sandboxKey]
	if containerName == "" {
		err := populateSandboxToContainer()
		if err != nil {
			logger.GetLogger().WithError(err).Warn("get container name failed")
			return ""
		}
		return sandboxToContainer[sandboxKey]
	}
	return containerName
}

func populateSandboxToContainer() error {
	newSandboxToContainer := make(map[string]string)
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		return err
	}

	for _, container := range containers {
		containerDetails, err := cli.ContainerInspect(ctx, container.ID)
		if err != nil {
			logger.GetLogger().WithError(err).WithField("container", container.ID).Warn("container details missing")
		}
		newSandboxToContainer[containerDetails.NetworkSettings.SandboxKey] = containerDetails.Name
	}
	sandboxToContainer = newSandboxToContainer
	return nil
}
