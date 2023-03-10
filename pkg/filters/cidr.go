// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package filters

import (
	"context"
	"fmt"

	stdNet "net"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/logger"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
	hubbleFilters "github.com/cilium/tetragon/pkg/oldhubble/filters"
	"k8s.io/utils/net"
)

// IPCIDRFilter filters on any IP field, including ProcessListen.ip
type IPCIDRFilter struct{}

func (f *IPCIDRFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc

	if ff.IpCidr != nil {
		filter, err := filterByCIDR(ff.IpCidr, f)
		if err != nil {
			return nil, err
		}
		fs = append(fs, filter)
	}

	return fs, nil
}

// SourceCIDRFilter filters on the source_ip field
type SourceCIDRFilter struct{}

func (f *SourceCIDRFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc

	if ff.SourceIpCidr != nil {
		filter, err := filterByCIDR(ff.SourceIpCidr, f)
		if err != nil {
			return nil, err
		}
		fs = append(fs, filter)
	}

	return fs, nil
}

// DestCIDRFilter filters on the destination_ip field
type DestCIDRFilter struct{}

func (f *DestCIDRFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc

	if ff.DestinationIpCidr != nil {
		filter, err := filterByCIDR(ff.DestinationIpCidr, f)
		if err != nil {
			return nil, err
		}
		fs = append(fs, filter)
	}

	return fs, nil
}

type cidrFilter struct {
	filterType filters.OnBuildFilter
	cidrs      []*stdNet.IPNet
}

// Get the IP field out of the event depending on the filter type
func (f *cidrFilter) getIPField(res *tetragon.GetEventsResponse) ([]string, bool) {
	switch f.filterType.(type) {
	// Any IP field including ProcessListen.Ip
	case *IPCIDRFilter:
		var ips []string
		ip, ok := getIP(res)
		if ok {
			ips = append(ips, ip)
		}
		ip, ok = getDestinationIP(res)
		if ok {
			ips = append(ips, ip)
		}
		ip, ok = getSourceIP(res)
		if ok {
			ips = append(ips, ip)
		}
		if len(ips) > 0 {
			return ips, true
		}
		return nil, false
	// Process*.SourceIp
	case *SourceCIDRFilter:
		ip, ok := getSourceIP(res)
		if ok {
			return []string{ip}, true
		}
	// Process*.DestinationIp
	case *DestCIDRFilter:
		ip, ok := getDestinationIP(res)
		if ok {
			return []string{ip}, true
		}
	default:
		logger.GetLogger().WithField("filter_type", fmt.Sprintf("%T", f)).Error("Unsupported CIDR filter type")
		// fall through to the return statement below
	}
	return nil, false
}

// Match CIDR based on list of CIDR strings and the event's IP field if it exists
func (f *cidrFilter) MatchCIDR(res *tetragon.GetEventsResponse) bool {
	// Events that don't have any IP field shouldn't match, so we return false here
	ips, ok := f.getIPField(res)
	if !ok {
		return false
	}

	// Parse IPs
	var addrs []stdNet.IP
	for _, ip := range ips {
		addrs = append(addrs, net.ParseIPSloppy(ip))
	}

	for _, cidr := range f.cidrs {
		for _, ipAddr := range addrs {
			if cidr.Contains(ipAddr) {
				return true
			}
		}
	}

	return false
}

func filterByCIDR(fs []string, f filters.OnBuildFilter) (hubbleFilters.FilterFunc, error) {
	const V6_CIDR_MASK = "/128"
	const V4_CIDR_MASK = "/32"

	cf := cidrFilter{
		filterType: f,
		cidrs:      []*stdNet.IPNet{},
	}

	for _, cidrString := range fs {
		// Check if IP and no cidr is provided, and if so convert into a full cidr
		if ip := net.ParseIPSloppy(cidrString); ip != nil {
			var mask string
			if ip.To4() != nil {
				mask = V4_CIDR_MASK
			} else {
				mask = V6_CIDR_MASK
			}
			_, cidr, err := net.ParseCIDRSloppy(cidrString + mask)
			if err != nil {
				return nil, err
			}
			cf.cidrs = append(cf.cidrs, cidr)
		} else {
			// Otherwise just try to parse the cidr
			_, cidr, err := net.ParseCIDRSloppy(cidrString)
			if err != nil {
				return nil, err
			}
			cf.cidrs = append(cf.cidrs, cidr)
		}

	}

	return func(ev *v1.Event) bool {
		res, ok := ev.Event.(*tetragon.GetEventsResponse)
		if !ok {
			return false
		}

		if cf.MatchCIDR(res) {
			return true
		}

		return false
	}, nil
}

type GetIP interface {
	GetIp() string
}

type GetSourceIP interface {
	GetSourceIp() string
}

type GetDestinationIP interface {
	GetDestinationIp() string
}

func getIP(res *tetragon.GetEventsResponse) (string, bool) {
	ev, ok := tetragon.UnwrapGetEventsResponse(res).(GetIP)
	if !ok {
		return "", false
	}
	return ev.GetIp(), true
}

func getSourceIP(res *tetragon.GetEventsResponse) (string, bool) {
	// If the event has socket info, use that instead
	if _, ok := tetragon.UnwrapGetEventsResponse(res).(GetSocket); ok {
		sockInfo, ok := getSockInfo(&v1.Event{Event: res})
		if !ok {
			return "", false
		}
		return sockInfo.SourceIp, ok
	}

	ev, ok := tetragon.UnwrapGetEventsResponse(res).(GetSourceIP)
	if !ok {
		return "", false
	}
	return ev.GetSourceIp(), true
}

func getDestinationIP(res *tetragon.GetEventsResponse) (string, bool) {
	// If the event has socket info, use that instead
	if _, ok := tetragon.UnwrapGetEventsResponse(res).(GetSocket); ok {
		sockInfo, ok := getSockInfo(&v1.Event{Event: res})
		if !ok {
			return "", false
		}
		return sockInfo.DestinationIp, ok
	}

	ev, ok := tetragon.UnwrapGetEventsResponse(res).(GetDestinationIP)
	if !ok {
		return "", false
	}
	return ev.GetDestinationIp(), true
}
