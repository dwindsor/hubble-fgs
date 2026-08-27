// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bench

import (
	"fmt"
	"net"
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const (
	senderName   = "fgsSender"
	receiverName = "fgsReceiver"
	senderNS     = "fgsBenchNsSenser"
	receiverNS   = "fgsBenchNsReceiver"
	senderIP     = "15.0.0.1/24"
	receiverIP   = "15.0.0.2/24"
)

func linkUp(ns *netns.NsHandle, name, n string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origns, _ := netns.Get()
	defer origns.Close()
	defer netns.Set(origns)

	if err := netns.Set(*ns); err != nil {
		return fmt.Errorf("netns.Set(): %s", err)
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("LinkByName(%s): %s", name, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("LinkSetup(%v): %s", link, err)
	}

	ip, _, err := net.ParseCIDR(n)
	if err != nil {
		return fmt.Errorf("ParseCIDR(%s): %s", n, err)
	}

	ipnet := &net.IPNet{
		IP:   ip,
		Mask: ip.DefaultMask(),
	}

	addr := &netlink.Addr{
		IPNet: ipnet,
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("netlink.AddrAdd(%s): %s", n, err)
	}

	_, subnet, err := net.ParseCIDR(n)
	if err != nil {
		return fmt.Errorf("ParseCIDR %s", err)
	}
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       subnet,
	}
	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("netlink.RouteAdd: %s", err)
	}

	return nil
}

func createInterface(ns *netns.NsHandle, name, ip string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("LinkByName(%s): %s", name, err)
	}

	if err := netlink.LinkSetNsFd(link, int(*ns)); err != nil {
		return fmt.Errorf("LinkSetNsFd(): %s", err)
	}

	if err := linkUp(ns, name, ip); err != nil {
		return fmt.Errorf("LinkUp(%s): %s", senderName, err)
	}
	return nil
}

func CreateVeth() error {
	veth := &netlink.Veth{
		Name:     senderName,
		PeerName: receiverName,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("LinkAdd (%v): %s", veth, err)
	}
	return nil
}

func CreateNetNs() (*netns.NsHandle, *netns.NsHandle, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origns, _ := netns.Get()
	defer origns.Close()

	send, err := netns.New()
	if err != nil {
		return nil, nil, fmt.Errorf("NewNamed(%s): %s", senderNS, err)
	}

	recv, err := netns.New()
	if err != nil {
		send.Close()
		return nil, nil, fmt.Errorf("NewNamed(%s): %s", receiverNS, err)
	}

	netns.Set(origns)
	return &send, &recv, nil
}

func ConfigureRouting() error {
	return nil
}
