package tc

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/sensors/unloader"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type NamespaceInterface struct {
	Ns uint64
	If string
}

var (
	progMap = make(map[*program.Program]*ebpf.Program)
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

func QdiscTCInsert(linkName string, _ bool) error {
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

func doLoadTC(un *unloader.TcUnloader, load *program.Program, prog *ebpf.Program, interfaces []string, nsNum uint64,
	existing map[NamespaceInterface]bool, allAttached map[NamespaceInterface]bool) error {
	allLinks, err := getAllRouteLinks()
	if err != nil {
		return err
	}
	attachLinks := filterLinks(allLinks, interfaces)

	for _, link := range attachLinks {
		// NOTE: Set outer 'err' and break on error to rewind.
		attachment := NamespaceInterface{Ns: nsNum, If: link.Attrs().Name}
		_, alreadyAttached := existing[attachment]
		if !alreadyAttached {
			logger.GetLogger().Infof("Attaching %s to device %s in net namespace %d", load.Type, link.Attrs().Name, nsNum)
			isIngress := load.Type == "tc_ingress"
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
		allAttached[attachment] = true
	}
	if err != nil {
		if unloadErr := un.Unload(); unloadErr != nil {
			logger.GetLogger().Warnf("Failed to unload on TC program rewind: %s", unloadErr)
		}
		return err
	}
	return nil
}

func LoadTC(
	bpfDir, mapDir, ciliumDir string,
	load *program.Program,
	verbose int,
	interfaces []string,
	attached map[NamespaceInterface]bool,
) (map[NamespaceInterface]bool, error) {
	allAttached := make(map[NamespaceInterface]bool)

	attach := func(prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {
		seenNs := make(map[uint64]bool)

		progMap[load] = prog

		procDir, err := os.ReadDir(option.Config.ProcFS)
		if err != nil {
			return nil, err
		}

		var un unloader.TcUnloader

		for _, process := range procDir {
			nsFileName := filepath.Join(option.Config.ProcFS, process.Name(), "ns/net")
			nsStr, err := os.Readlink(nsFileName)
			if err != nil {
				continue
			}
			if !strings.HasPrefix(nsStr, "net:[") {
				continue
			}
			nsNum, err := strconv.ParseUint(nsStr[5:len(nsStr)-1], 10, 64)
			if err != nil {
				continue
			}

			_, seen := seenNs[nsNum]
			if seen {
				continue
			}

			seenNs[nsNum] = true

			netns, err := ns.GetNS(nsFileName)
			if err != nil {
				logger.GetLogger().WithField("pid", os.Getpid()).WithField("file", nsFileName).WithError(err).Infof("GetNS from path failed")
				continue
			}

			err = netns.Do(func(_ ns.NetNS) error {
				err = doLoadTC(&un, load, prog, interfaces, nsNum, attached, allAttached)
				if err != nil {
					return err
				}
				return nil
			})
			netns.Close()
			if err != nil {
				return nil, err
			}
		}

		chainUn := unloader.ChainUnloader{
			unloader.PinUnloader{
				Prog: prog,
			},
			&un,
		}
		return chainUn, nil
	}

	p, exists := progMap[load]
	if exists {
		if p.FD() != -1 {
			_, err := attach(p, nil)
			return allAttached, err
		}
		delete(progMap, load)
	}

	return allAttached, program.LoadProgram(bpfDir, []string{mapDir, ciliumDir}, load, attach, verbose)
}
