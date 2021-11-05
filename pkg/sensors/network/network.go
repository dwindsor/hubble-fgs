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
	"time"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
	"github.com/vishvananda/netlink"
)

var (
	NetworkStatInterval = time.Duration(60 * time.Second)
)

func emitInterfaceEvent(attrs *netlink.LinkAttrs) {
	unix := api.MsgInterfaceEventUnix{
		Common: api.MsgCommon{
			Op:    api.MSG_OP_INTERFACE_STATS,
			Size:  1,
			Ktime: 0,
		},
		Iface: api.MsgInterface{
			Index: attrs.Index,
			Name:  attrs.Name,
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
			emitInterfaceEvent(l.Attrs())
		}
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

func (net *networkSensor) LoadProbe(args sensors.LoadProbeArgs) (error, int) {
	return nil, 0
}

func EnableNetworkParser() *sensors.Sensor {
	defaultCBInterval := NetworkStatInterval

	logger.GetLogger().Infof("Enable Interface Statistics")
	networkCB(defaultCBInterval)
	return nil
}

func (net *networkSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
	if !spec.Parser.Interface.Enable {
		return nil, nil
	}
	return EnableNetworkParser(), nil
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
