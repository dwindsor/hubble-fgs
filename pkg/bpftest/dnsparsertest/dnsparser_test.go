// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build sudo_tests

package dnsparsertest

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/isovalent/hubble-fgs/pkg/bpftest"
	"github.com/isovalent/hubble-fgs/pkg/dnsparser"
	"github.com/isovalent/hubble-fgs/pkg/option"

	_ "github.com/isovalent/hubble-fgs/pkg/sensors/exec"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

func TestDNSParserPerPodFeature(t *testing.T) {
	if !utils.SupportDNSParser() || !utils.SockopsSupportsCgroupAncestorHelper() {
		t.Skip()
	}

	option.Config.EnableBPFDNSPerPod = true
	option.Config.BPFDNSPerPodPrealloc = 6
	option.Config.BPFDNSPerPodThresold = 2
	arbitraryCgroupID := uint64(666)
	dnsparser.GetKubepodsSliceCgroupID = func() (uint64, error) {
		return arbitraryCgroupID, nil
	}
	bpftest.StartMinimalTetragonModel(context.Background(), t)

	// check that at least the pre-allocated map are pinned
	for index := range option.Config.BPFDNSPerPodPrealloc {
		_, err := os.Stat(filepath.Join(bpf.MapPrefixPath(), fmt.Sprintf("%s_%d", dnsparser.IPToIDMapsName, index)))
		require.NoError(t, err, "map should have been pre-allocated and pinned")
	}

	// check that consts have been rewritten (and thus program should load and pass the verifier)
	// this is not super solid and might break but we need at least a test that loads this feature
	cmdArgs := []string{"--json", "map", "dump", "name", ".rodata"}
	cmd := exec.Command("bpftool", cmdArgs...)
	output, err := cmd.Output()
	require.NoError(t, err)
	outputString := string(output)

	assert.Contains(t, outputString, fmt.Sprintf("\"%s\":%d", dnsparser.KubepodsCgidConstName, arbitraryCgroupID))

	// DNS_PARSER_PER_POD_ENABLED and DNS_PARSER_ENABLED live in hubble-fgs's
	// own fgs_rodata_config map rather than as per-program rewritten
	// constants, so they don't show up in the generic ".rodata" dump above -
	// check the pinned map directly.
	fgsRodataMap, err := ebpf.LoadPinnedMap(filepath.Join(bpf.MapPrefixPath(), "fgs_rodata_config"), nil)
	require.NoError(t, err)
	defer fgsRodataMap.Close()

	contents, err := fgsRodataMap.LookupBytes(uint32(0))
	require.NoError(t, err)
	require.Len(t, contents, 14)
	assert.Equal(t, byte(1), contents[0], "DNS_PARSER_PER_POD_ENABLED flag")
	if utils.SupportProcessTree() {
		assert.Equal(t, byte(1), contents[3], "DNS_PARSER_ENABLED flag")
	}
}

func startMockDNSServer(t *testing.T, listenPort uint16, mockDomain string, mockIP string) func() {
	t.Helper()

	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		if len(r.Question) > 0 {
			q := r.Question[0]
			if q.Qtype == dns.TypeA && strings.EqualFold(q.Name, mockDomain+".") {
				rr, err := dns.NewRR(mockDomain + ". 60 IN A " + mockIP)
				if err == nil {
					m.Answer = []dns.RR{rr}
				}
			} else {
				m.Rcode = dns.RcodeNameError // NXDOMAIN
			}
		}

		_ = w.WriteMsg(m)
	}

	dns.HandleFunc(".", handler)

	addr := fmt.Sprintf(":%d", listenPort)
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("failed to bind UDP %s: %v", addr, err)
	}

	srv := &dns.Server{
		PacketConn: pc,
		Net:        "udp",
	}

	done := make(chan struct{})
	go func() {
		if err := srv.ActivateAndServe(); err != nil {
			t.Logf("DNS server stopped: %v", err)
		}
		close(done)
	}()

	return func() {
		_ = srv.Shutdown()
		dns.HandleRemove(".")
		<-done
	}
}

func TestDNSParserPortsOptions(t *testing.T) {
	if !utils.SupportDNSParser() {
		t.Skip()
	}
	// Technically, the process tree reqs don't limit the DNS parser, but as
	// of now, on kernels that don't support it, we load the dispatcherProgs
	// versions (vs dispatcherProcessTree* versions) that don't include the
	// parser (because IN_KERNEL_DNS is not defined). This is typically the
	// version loaded on rhel8 or upstream until 5.15 (surprisingly, rhel8
	// will pass SupportDNSParser while 5.10 will not).
	if !utils.SupportProcessTree() {
		t.Skip()
	}

	const firstPort, secondPort = 8080, 9090
	const firstIP, secondIP = "1.2.3.4", "5.6.7.8"
	const firstDomain, secondDomain = "example1.com", "example2.com"

	option.Config.DNSPorts = []int{firstPort, secondPort}
	bpftest.StartMinimalTetragonModel(context.Background(), t)

	shutdown1 := startMockDNSServer(t, firstPort, firstDomain, firstIP)
	r1 := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second,
			}
			return d.DialContext(ctx, network, fmt.Sprintf(":%d", firstPort))
		},
	}
	ips, err := r1.LookupIP(context.Background(), "ip4", firstDomain)
	require.Len(t, ips, 1)
	assert.Equal(t, firstIP, ips[0].String())
	require.NoError(t, err)
	shutdown1()

	shutdown2 := startMockDNSServer(t, secondPort, secondDomain, secondIP)
	r2 := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second,
			}
			return d.DialContext(ctx, network, fmt.Sprintf(":%d", secondPort))
		},
	}
	ips, err = r2.LookupIP(context.Background(), "ip4", secondDomain)
	require.Len(t, ips, 1)
	assert.Equal(t, secondIP, ips[0].String())
	require.NoError(t, err)
	shutdown2()

	ipToIDMapsPath := bpf.MapPath(dnsparser.IPToIDMapsName)
	rawIPToIDMaps, err := ebpf.LoadPinnedMap(ipToIDMapsPath, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		rawIPToIDMaps.Close()
	})
	ipToIDMaps := dnsparser.NewIPToIDMaps(rawIPToIDMaps)

	t.Log(ipToIDMaps.Values(dnsparser.DefaultInnerMapID))

	_, err = ipToIDMaps.Lookup(dnsparser.DefaultInnerMapID, netip.MustParseAddr("9.9.9.9"))
	require.ErrorIs(t, err, ebpf.ErrKeyNotExist)
	_, err = ipToIDMaps.Lookup(dnsparser.DefaultInnerMapID, netip.MustParseAddr(firstIP))
	require.NoError(t, err)
	_, err = ipToIDMaps.Lookup(dnsparser.DefaultInnerMapID, netip.MustParseAddr(secondIP))
	require.NoError(t, err)
}
