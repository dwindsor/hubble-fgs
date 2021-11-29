package udp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/yalue/native_endian"

	"golang.org/x/net/dns/dnsmessage"
)

var (
	defaultDnsPort = 53
)

var (
	dnsPort = defaultDnsPort
)

func handleUdpPayload(r *bytes.Reader) ([]observer.ObserverEvent, error) {
	m := api.MsgIPv4Event{}
	err := binary.Read(r, native_endian.NativeEndian(), &m)
	if err != nil {
		return nil, err
	}
	if uint16(dnsPort) == m.Tuple.SPort || uint16(dnsPort) == m.Tuple.DPort {
		return handleUdpDns(&m, r)
	}
	return nil, fmt.Errorf("handleUdpPayload: unknown payload protocol")
}

func handleUdpDns(m *api.MsgIPv4Event, r *bytes.Reader) ([]observer.ObserverEvent, error) {
	var p dnsmessage.Parser

	// Annotate msg with user space parser op type
	m.Common.Op = api.MSG_OP_IPV4_DNS

	buf := make([]byte, int(m.Common.Size)-int(unsafe.Sizeof(m)))

	if _, err := r.Read(buf); err != nil {
		return nil, err
	}

	var ips []net.IP
	var ipStrings []string
	var aTypes []uint32
	var qTypes []uint32
	var names []string

	hdr, err := p.Start(buf)
	if err != nil {
		return nil, err
	}

	qs, err := p.AllQuestions()
	if err != nil {
		return nil, err
	}

	for _, q := range qs {
		names = append(names, q.Name.String())
	}

	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, err
		}

		if (h.Type != dnsmessage.TypeA && h.Type != dnsmessage.TypeAAAA) || h.Class != dnsmessage.ClassINET {
			continue
		}

		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return nil, err
			}
			ips = append(ips, r.A[:])
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return nil, err
			}
			ips = append(ips, r.AAAA[:])
		}
		aTypes = append(aTypes, uint32(h.Type))
	}

	for _, ip := range ips {
		ipStrings = append(ipStrings, ip.String())
	}

	msgDns := api.MsgDns{
		RCode:         uint16(hdr.RCode),
		AnswerTypes:   aTypes,
		QuestionTypes: qTypes,
		Names:         names,
		IPs:           ipStrings,
	}

	msgUnix := &api.MsgIPv4DnsUnix{
		Common:     m.Common,
		Tuple:      m.Tuple,
		Return:     m.Return,
		ProcessKey: m.ProcessKey,
		SockCookie: m.SockCookie,
		Dns:        msgDns,
	}
	return []observer.ObserverEvent{msgUnix}, nil
}

// ParseDNSSepec parsesthe input yaml/crd and outputs the kernel selectors
// needed for BPF to identify DNS and run DNS parser on it.
//
// DNS selector layout is the following.
// #OfMatchPorts uint32
// Port1 ... PortN uint32, uint32, ...
func ParseDnsSpec(spec *v1alpha1.TracingPolicySpec) ([128]byte, error) {
	var match [128]byte

	return match, nil
}
