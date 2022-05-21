package tc

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program"
	"github.com/isovalent/hubble-fgs/pkg/sensors/unloader"
	"github.com/vishvananda/netlink"
)

func getDefaultRouteLinks() ([]netlink.Link, error) {
	var links []netlink.Link

	nilDst := &netlink.Route{Dst: nil}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, nilDst, netlink.RT_FILTER_DST)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Failed to list selectored routes")
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

func LoadTC(
	bpfDir, mapDir, ciliumDir string,
	load *program.Program,
	version, verbose int,
	selectors [128]byte,
) error {
	attach := func(prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {
		attachLinks, err := getDefaultRouteLinks()
		if err != nil {
			return nil, err
		}
		var un unloader.TcUnloader
		for _, link := range attachLinks {
			// NOTE: Set outer 'err' and break on error to rewind.
			logger.GetLogger().Infof("Attaching %s to device %s", load.Type, link.Attrs().Name)
			isIngress := "tc_ingress" == load.Type
			if err = bpf.QdiscTCInsert(link.Attrs().Name, isIngress); err != nil {
				break
			}
			if err = bpf.AttachTCIngress(prog.FD(), link.Attrs().Name, isIngress); err != nil {
				break
			}
			un.Attachments = append(un.Attachments, unloader.TcAttachment{link.Attrs().Name, isIngress})
		}
		if err != nil {
			if unloadErr := un.Unload(); unloadErr != nil {
				logger.GetLogger().Warnf("Failed to unload on TC program rewind: %s", unloadErr)
			}
			return nil, err
		}
		return un, nil
	}
	return program.LoadProgram(bpfDir, []string{mapDir, ciliumDir}, load, attach)
}
