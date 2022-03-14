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
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Unloader describes how to unload a sensor resource, e.g.
// programs or maps.
type Unloader interface {
	Unload() error
}

// chainUnloader is an unloader for multiple resources.
// Useful when a loading operation needs to be unwinded due to an error.
type chainUnloader []Unloader

type chainUnloaderErrors struct {
	errors []error
}

func (cue chainUnloaderErrors) Error() string {
	strs := []string{}
	for _, e := range cue.errors {
		strs = append(strs, e.Error())
	}
	return strings.Join(strs, "; ")
}

func (cu chainUnloader) Unload() error {
	var cue chainUnloaderErrors
	for i := len(cu) - 1; i >= 0; i-- {
		if err := (cu)[i].Unload(); err != nil {
			cue.errors = append(cue.errors, err)
		}
	}
	if len(cue.errors) > 0 {
		return cue
	}
	return nil
}

// pinUnloader unpins and closes a BPF program.
type pinUnloader struct {
	prog *ebpf.Program
}

func (pu pinUnloader) Unload() error {
	err := pu.prog.Unpin()
	err2 := pu.prog.Close()
	if err != nil {
		return err
	}
	return err2
}

// linkUnloader unloads a BPF link by closing it.
type linkUnloader struct {
	link link.Link
}

func (lu linkUnloader) Unload() error {
	return lu.link.Close()
}

// rawDetachUnloader can be used to unload cgroup and sockmap programs.
type rawDetachUnloader struct {
	targetFD   int
	name       string
	prog       *ebpf.Program
	attachType ebpf.AttachType
}

func (rdu *rawDetachUnloader) Unload() error {
	err := link.RawDetachProgram(link.RawDetachProgramOptions{
		Target:  rdu.targetFD,
		Program: rdu.prog,
		Attach:  rdu.attachType,
	})
	if err != nil {
		return fmt.Errorf("failed to detach %s: %w", rdu.name, err)
	}
	return nil
}

// tcUnloader unloads programs attached to TC filters
type tcUnloader struct {
	attachments []tcAttachment
}

type tcAttachment struct {
	linkName  string
	isIngress bool
}

func (tu tcUnloader) Unload() error {
	for _, att := range tu.attachments {
		if err := detachTC(att.linkName, att.isIngress); err != nil {
			return err
		}
	}
	return nil
}

func detachTC(linkName string, ingress bool) error {
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
		Name:         name,
		DirectAction: true,
	}
	if filter.Fd < 0 {
		return fmt.Errorf("BpfFilter failed (%s): %d", linkName, filter.Fd)
	}
	if err = netlink.FilterDel(filter); err != nil {
		return fmt.Errorf("FilterDel failed (%s): %w", linkName, err)
	}
	return err

}
