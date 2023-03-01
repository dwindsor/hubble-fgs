package tc

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/sensors/unloader"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func getAllRouteLinks() ([]netlink.Link, error) {
	allLinks, err := netlink.LinkList()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Failed to list links")
		return nil, err
	}
	return allLinks, nil
}

func inInterfaces(i string, interfaces []string) bool {
	for _, s := range interfaces {
		if s == i {
			return true
		}
	}
	return false
}

func filterLinks(links []netlink.Link, interfaces []string) []netlink.Link {
	if len(interfaces) == 0 {
		return links
	}
	var filtered []netlink.Link
	for _, link := range links {
		if inInterfaces(link.Attrs().Name, interfaces) {
			filtered = append(filtered, link)
		}
	}
	return filtered
}

func QdiscTCInsert(linkName string, ingress bool) error {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("LinkByName failed (%s): %w", linkName, err)
	}

	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("QdiscList failed (%s): %w", linkName, err)
	}
	// If the qdisc exists nothing to do so return nil
	for _, qdisc := range qdiscs {
		_, clsact := qdisc.(*netlink.Clsact)
		if clsact {
			return nil
		}
	}

	qdisc := &netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_INGRESS,
		},
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		return fmt.Errorf("QdiscAdd failed (%s): %w", linkName, err)
	}
	return nil
}

func AttachTCIngress(progFd int, linkName string, ingress bool) error {
	var parent uint32
	var name string

	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("LinkByName failed (%s): %w", linkName, err)
	}

	if ingress {
		parent = netlink.HANDLE_MIN_INGRESS
		name = "fgs-ingress"
	} else {
		parent = netlink.HANDLE_MIN_EGRESS
		name = "fgs-egress"
	}

	filterAttrs := netlink.FilterAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    parent,
		Handle:    netlink.MakeHandle(0, 2),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}
	filter := &netlink.BpfFilter{
		FilterAttrs:  filterAttrs,
		Fd:           progFd,
		Name:         name,
		DirectAction: true,
	}
	if filter.Fd < 0 {
		return fmt.Errorf("BpfFilter failed (%s): %d", linkName, filter.Fd)
	}
	if err = netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("FilterAdd failed (%s): %w", linkName, err)
	}
	return err
}

func LoadTC(
	bpfDir, mapDir, ciliumDir string,
	load *program.Program,
	version, verbose int,
	selectors [128]byte,
	interfaces []string,
) error {
	attach := func(prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {
		allLinks, err := getAllRouteLinks()
		if err != nil {
			return nil, err
		}
		attachLinks := filterLinks(allLinks, interfaces)
		var un unloader.TcUnloader
		for _, link := range attachLinks {
			// NOTE: Set outer 'err' and break on error to rewind.
			logger.GetLogger().Infof("Attaching %s to device %s", load.Type, link.Attrs().Name)
			isIngress := "tc_ingress" == load.Type
			if err = QdiscTCInsert(link.Attrs().Name, isIngress); err != nil {
				logger.GetLogger().WithError(err).Warn("QdiscTCInsert Failed")
				break
			}
			if err = AttachTCIngress(prog.FD(), link.Attrs().Name, isIngress); err != nil {
				logger.GetLogger().WithError(err).Warn("AttachTC Failed")
				break
			}
			un.Attachments = append(un.Attachments,
				unloader.TcAttachment{
					LinkName:  link.Attrs().Name,
					IsIngress: isIngress,
				})
		}
		if err != nil {
			if unloadErr := un.Unload(); unloadErr != nil {
				logger.GetLogger().Warnf("Failed to unload on TC program rewind: %s", unloadErr)
			}
			return nil, err
		}
		chainUn := unloader.ChainUnloader{
			unloader.PinUnloader{
				Prog: prog,
			},
			&un,
		}
		return chainUn, nil
	}
	return program.LoadProgram(bpfDir, []string{mapDir, ciliumDir}, load, attach, verbose)
}
