package dnsapi

import (
	"golang.org/x/net/dns/dnsmessage"
)

type MsgDns struct {
	Response      bool
	RCode         uint16
	AnswerTypes   []uint32
	QuestionTypes []uint32
	Names         []string
	IPs           []string
}

// All Type constants defined in golang.org/x/net/dns/dnsmessage/message.go
var KnownDNSTypes = []dnsmessage.Type{
	dnsmessage.TypeA,
	dnsmessage.TypeNS,
	dnsmessage.TypeCNAME,
	dnsmessage.TypeSOA,
	dnsmessage.TypePTR,
	dnsmessage.TypeMX,
	dnsmessage.TypeTXT,
	dnsmessage.TypeAAAA,
	dnsmessage.TypeSRV,
	dnsmessage.TypeOPT,
	dnsmessage.TypeWKS,
	dnsmessage.TypeHINFO,
	dnsmessage.TypeMINFO,
	dnsmessage.TypeAXFR,
	dnsmessage.TypeALL,
}
