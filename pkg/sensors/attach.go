//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package sensors

import (
	"path/filepath"

	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/btf"
	"github.com/isovalent/hubble-fgs/pkg/logger"

	"github.com/vishvananda/netlink"
)

func LoadSockOpt(
	bpfDir, mapDir, ciliumDir string,
	load *Program,
	version, verbose int,
	x64 bool,
	path string,
) (error, int) {
	btfObj := uintptr(btf.GetCachedBTF())
	return bpf.LoadSockOptProgram(
		version, verbose,
		btfObj,
		load.Name,
		load.Label,
		filepath.Join(bpfDir, load.PinPath),
		mapDir,
		path,
	)
}

func LoadSkmsg(
	bpfDir, mapDir, ciliumDir string,
	load *Program,
	version, verbose int,
	x64 bool,
	path string,
) (error, int) {
	btfObj := uintptr(btf.GetCachedBTF())
	return bpf.LoadSkmsgProgram(
		version, verbose,
		btfObj,
		load.Name,
		load.Label,
		filepath.Join(bpfDir, load.PinPath),
		mapDir,
		path,
	)
}

func LoadSkSkbVerdict(
	bpfDir, mapDir, ciliumDir string,
	load *Program,
	version, verbose int,
	x64 bool,
	path string,
) (error, int) {
	btfObj := uintptr(btf.GetCachedBTF())
	return bpf.LoadSkSkbVerdictProgram(
		version, verbose,
		btfObj,
		load.Name,
		load.Label,
		filepath.Join(bpfDir, load.PinPath),
		mapDir,
		path,
	)
}

func LoadSkSkbParser(
	bpfDir, mapDir, ciliumDir string,
	load *Program,
	version, verbose int,
	x64 bool,
	path string,
) (error, int) {
	btfObj := uintptr(btf.GetCachedBTF())
	return bpf.LoadSkSkbParserProgram(
		version, verbose,
		btfObj,
		load.Name,
		load.Label,
		filepath.Join(bpfDir, load.PinPath),
		mapDir,
		path)
}

func LoadSockops(
	bpfDir, mapDir, ciliumDir string,
	load *Program,
	version, verbose int,
	x64 bool,
	tls_filters, http_filters [128]byte,
) (error, int) {
	btfObj := uintptr(btf.GetCachedBTF())
	return bpf.LoadSockopsProgram(version, verbose, btfObj,
		load.Name,
		load.Label,
		filepath.Join(bpfDir, load.PinPath),
		mapDir,
		tls_filters, http_filters,
	)
}

func LoadTC(
	bpfDir, mapDir, ciliumDir string,
	load *Program,
	version, verbose int,
	filters [128]byte,
) (error, int) {
	var attachLinks []netlink.Link

	btfObj := uintptr(btf.GetCachedBTF())
	err, fd := bpf.LoadTC(
		version, verbose,
		btfObj,
		load.Name,
		load.Label,
		filepath.Join(bpfDir, load.PinPath),
		mapDir,
		ciliumDir,
		filters,
	)
	if err != nil {
		return err, fd
	}
	attachLinks, err = getDefaultRouteLinks()
	if err != nil {
		return err, 0
	}

	for _, link := range attachLinks {
		logger.GetLogger().Infof("Attaching %s to device %s", load.Type, link.Attrs().Name)
		isIngress := "tc_ingress" == load.Type
		if err = bpf.QdiscTCInsert(link.Attrs().Name, isIngress); err != nil {
			return err, 0
		}
		bpf.AttachTCIngress(fd, link.Attrs().Name, isIngress)
	}

	return nil, 0
}

func getDefaultRouteLinks() ([]netlink.Link, error) {
	var links []netlink.Link

	nilDst := &netlink.Route{Dst: nil}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, nilDst, netlink.RT_FILTER_DST)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Failed to list filtered routes")
		return nil, err
	}
	allLinks, err := netlink.LinkList()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Failed to list links")
		return nil, err
	}
	for _, route := range routes {
		for _, link := range allLinks {
			if link.Attrs().Index == route.LinkIndex {
				links = append(links, link)
			}
		}
	}
	return links, nil
}
