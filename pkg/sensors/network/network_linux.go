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
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"github.com/isovalent/hubble-fgs/pkg/nscache"
)

func emitNSEvent() {

	cache := nscache.GetCache()
	values := cache.Values()
	for _, v := range values {
		pidStr := strconv.FormatUint(uint64(v.Pid), 10)
		nsFileName := filepath.Join(option.Config.ProcFS, pidStr, "ns", "net")
		netns, err := ns.GetNS(nsFileName)
		if err != nil {
			logger.GetLogger().Debug("runNetworkCB GetNS from path failed", "pid", os.Getpid(), "file", nsFileName, logfields.Error, err)
			nscache.DelNetNs(v.Netns)
			continue
		}
		defer netns.Close()

		_ = netns.Do(func(_ ns.NetNS) error {
			links, err := netlink.LinkList()
			if err != nil {
				logger.GetLogger().Info("netns LinkList failed", "pid", os.Getpid(), "file", nsFileName, logfields.Error, err)
				return fmt.Errorf("netlink LinkList() error: %v", err)
			}
			for _, l := range links {
				emitInterfaceEvent(l.Attrs(), v.Netns, v.Pod)
			}
			return nil
		})
	}
}
