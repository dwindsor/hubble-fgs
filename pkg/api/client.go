//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package api

import (
	"encoding/binary"
	"fmt"

	"github.com/isovalent/hubble-fgs/pkg/api/processapi"
	"github.com/isovalent/hubble-fgs/pkg/vtuple"
)

const (
	SNI_BUFFER_SIZE = 64
)

// TLS supported version 8bit codes
const (
	TLSVersion13 = 0x0403
	TLSVersion12 = 0x0303
	TLSVersion11 = 0x0203
	TLSVersion10 = 0x0103
	TLSNone      = 0x0000
)

// TLS flags
const (
	TlsFlagCopyError           = 0x0001
	TlsFlagMaxTlvs             = 0x0002
	TlsFlagFrameTooLarge       = 0x0004
	TlsFlagHelloMsgMiss        = 0x0008
	TlsFlagCipherError         = 0x0010
	TlsFlagCipherTooLarge      = 0x0020
	TlsFlagCompressionError    = 0x0040
	TlsFlagCompressionTooLarge = 0x0080
	TlsFlagExtError            = 0x0100
	TlsFlagExtTooLarge         = 0x0200
	TlsFlagVersion             = 0x0400
	TlsFlagCert                = 0x0800
	TlsFlagHandshakeMsgMiss    = 0x1000
)

// TLS Certificate Errors
const (
	TlsCertificateErrorNone      = 0x0000
	TlsCertificateErrorBadHeader = 0x0001
	// Userspace errors
	TlsCertificateErrorLengthRead    = 0x0100
	TlsCertificateErrorMissingError  = 0x0200
	TlsCertificateErrorCertRead      = 0x0400
	TlsCertificateErrorCertPartial   = 0x0800
	TlsCertificateErrorParseX509     = 0x1000
	TlsCertificateErrorSpuriousCerts = 0x2000
)

// Socket Flags
const (
	SOCKFLAGS_TYPE_UNKNOWN = 0x0
	SOCKFLAGS_TYPE_CONNECT = 0x1
	SOCKFLAGS_TYPE_ACCEPT  = 0x2
	SOCKFLAGS_TYPE_LISTEN  = 0x4
	// User space flag space 0x00F0
	SOCKFLAGS_TYPE_DNSREADY = 0x10
)

type MsgFGSReady struct{}

type MsgIPv4Tuple struct {
	SAddr uint32
	DAddr uint32
	DPort uint16
	SPort uint16
	Proto uint8
	// define as uint8 otherwise padding in struct breaks
	PostData [6]uint8
	Pad      [5]uint8
}

func (m *MsgIPv4Tuple) GetPostDAddr() uint32 {
	return binary.LittleEndian.Uint32(m.PostData[0:4])
}

func (m *MsgIPv4Tuple) GetPostDPort() uint16 {
	return binary.LittleEndian.Uint16(m.PostData[4:6])
}

type MsgIPv4Event struct {
	Common      processapi.MsgCommon    `align:"common"`
	Tuple       MsgIPv4Tuple            `align:"tuple"`
	Return      int64                   `align:"ret"`
	ProcessKey  processapi.MsgExecveKey `align:"key"`
	SockCookie  uint64                  `align:"socket_cookie"`
	SocketStats MsgSocketStats          `align:"stats"`
	SocketFlags uint32                  `align:"socket_flags"`
	Pad         uint32                  `align:"pad"`
}

type MsgDns struct {
	Response      bool
	RCode         uint16
	AnswerTypes   []uint32
	QuestionTypes []uint32
	Names         []string
	IPs           []string
}

type MsgIPv4DnsUnix struct {
	Common     processapi.MsgCommon
	Tuple      MsgIPv4Tuple
	Return     int64
	ProcessKey processapi.MsgExecveKey
	SockCookie uint64
	Dns        MsgDns
}

type MsgCalltrace struct {
	Stack [16]uint64
	Ret   int32
}

type MsgSocketStatsUnix struct {
	BytesSubmitted  uint64
	BytesSent       uint64
	BytesConsumed   uint64
	BytesReceived   uint64
	ConsumedSegs    uint32
	SegsIn          uint32
	SubmittedSegs   uint32
	SegsOut         uint32
	SRtt            uint32
	RetransmitSegs  uint32
	RetransmitBytes uint64
	ToZeroWindow    uint32
	SkDrop          uint32
}

type MsgSocketStats struct {
	BytesSent       uint64
	BytesReceived   uint64
	SegsIn          uint32
	SegsOut         uint32
	SRtt            uint32
	RetransmitSegs  uint32
	RetransmitBytes uint64
	ToZeroWindow    uint32
	SkDrop          uint32
}

type MsgIPv4EventUnix struct {
	Common      processapi.MsgCommon
	Tuple       MsgIPv4Tuple
	Kube        processapi.MsgK8sUnix
	Return      int64
	ProcessKey  processapi.MsgExecveKey
	SockCookie  uint64
	SocketStats MsgSocketStatsUnix
	SocketFlags uint32
}

type MsgInterfaceStats struct {
	BytesSent       uint64
	BytesReceived   uint64
	PacketsSent     uint64
	PacketsReceived uint64
	TxErrors        uint64
	RxErrors        uint64
	RxDrops         uint64
	TxDrops         uint64
}

type MsgInterface struct {
	Name          string
	Index         int
	Netns         string
	ContainerName string
}

type MsgInterfaceEventUnix struct {
	Common processapi.MsgCommon
	Kube   processapi.MsgK8sUnix
	Iface  MsgInterface
	Stats  MsgInterfaceStats
}

var MsgUnixSize uint32 = 640

type MsgTLSIPv4 struct {
	SAddr     uint32
	DAddr     uint32
	DPort     uint16
	SPort     uint16
	Remaining uint32
	Uid       uint64
}

// FLV64 is a length-value pair with a maximum length of 64 bytes
type FLV64 struct {
	Length uint8
	Value  [64]uint8
}

func (flv *FLV64) Bytes() ([]byte, error) {
	var err error
	length := flv.Length
	if flv.Length > 64 {
		err = fmt.Errorf("value truncated from %d to 64", flv.Length)
		length = 64
	}
	return flv.Value[:length], err
}

// FLV16 is a length-value pair with a maximum length of 16 bytes
type FLV16 struct {
	Length uint8
	Value  [16]uint8
}

func (flv *FLV16) Bytes() ([]byte, error) {
	var err error
	length := flv.Length
	if flv.Length > 16 {
		err = fmt.Errorf("value truncated from %d to 16", flv.Length)
		length = 16
	}
	return flv.Value[:length], err
}

type MsgTLS struct {
	Version           uint16
	Length            uint16
	Type              uint8
	Subtype           uint8
	LegacyyVersion    uint16
	Flags             uint32
	Bytes             uint32
	AlertLevel        uint8
	AlertDescription  uint8
	Session           FLV64
	Cipher            FLV64
	SNI               FLV64
	SupportedVersions FLV16
}

type MsgTLSParserState struct {
	Length  uint32
	Type    uint32
	Subtype uint32
	Offset  uint32
}

func (s *MsgTLSParserState) String() string {
	if s.Length != 0 || s.Type != 0 || s.Subtype != 0 || s.Offset != 0 {
		return fmt.Sprintf("len=%d:type=%d:subtype=%d:offset=%d", s.Length, s.Type, s.Subtype, s.Offset)
	}
	return ""
}

type MsgTLSCertificates struct {
	Certificates []string
	Error        uint32
	// Error Info useful for bug reports
	ParserState MsgTLSParserState
}

type MsgTLSAlert struct {
	Level       uint8
	Description uint8
	Count       uint16
}

type MsgTLSEvent struct {
	Common      processapi.MsgCommon    `align:"common"`
	Tuple       MsgTLSIPv4              `align:"tuple"`
	ClientHello MsgTLS                  `align:"clienthello"`
	ServerHello MsgTLS                  `align:"serverhello"`
	ProcessKey  processapi.MsgExecveKey `align:"execve"`
}

type MsgTLSEventUnix struct {
	Common      processapi.MsgCommon
	Tuple       MsgTLSIPv4
	ClientHello MsgTLS
	ServerHello MsgTLS
	ServerCert  MsgTLSCertificates
	ProcessKey  processapi.MsgExecveKey
}

const (
	HTTP_METHOD_POST = 1
	HTTP_METHOD_GET  = 2
)

type HttpKey struct {
	Tuple MsgIPv4Tuple
	Id    uint64
}

type MsgHttpUnix struct {
	Method               string
	Uri                  string
	Host                 string
	Protocol             string
	UserAgent            string
	ContentLength        string
	RespContentLength    string
	Code                 string
	Reason               string
	RespVersion          string
	RequestId            uint64
	Ktime                uint64
	Flags                uint32
	FlagsResponse        uint32
	TransferEncoding     string
	RespTransferEncoding string
}

type MsgHttp struct {
	Method uint32
	Flags  uint32
	ReqId  uint64
	RespId uint64
	Url    [1024]byte
	Pad1   uint32
	Pad2   uint32
	Pad3   uint32
}

type MsgHttpEventUnix struct {
	Common     processapi.MsgCommon
	Tuple      MsgIPv4Tuple
	ProcessKey processapi.MsgExecveKey
	Request    MsgHttpUnix
}

type MsgHttpEvent struct {
	Common     processapi.MsgCommon
	Tuple      MsgIPv4Tuple
	ProcessKey processapi.MsgExecveKey
	Request    MsgHttp
}

type MsgCredEvent struct {
	Common       processapi.MsgCommon       `align:"common"`
	ProcessKey   processapi.MsgExecveKey    `align:"current"`
	Capabilities processapi.MsgCapabilities `align:"caps"`
}

type MsgCredEventUnix = MsgCredEvent

type MsgProcessNetworkBurstEvent struct {
	Common        processapi.MsgCommon
	ProcessKey    processapi.MsgExecveKey
	Protocol      uint32 // IP protocol
	BurstStartDir uint32 // b0=start of burst, otherwise end of burst, b16=egress, otherwise ingress
	WindowSize    uint64 // Nanoseconds
	HistAvg       uint64 // Bytes per WindowSize
	HistTrigger   uint64 // Bytes per WindowSize trigger level
	WindowAvg     uint64 // Bytes seen in WindowSize
}

type MsgProcessNetworkBurstEventUnix = MsgProcessNetworkBurstEvent

type MsgTestEvent struct {
	Common processapi.MsgCommon `align:"common"`
	Arg0   uint64               `align:"arg0"`
	Arg1   uint64               `align:"arg1"`
	Arg2   uint64               `align:"arg2"`
	Arg3   uint64               `align:"arg3"`
}

type MsgTestEventUnix = MsgTestEvent

type SensorStatus struct {
	Name    string
	Enabled bool
}

func SwapByte(b uint16) uint16 {
	return (b << 8) | (b >> 8)
}

type MsgKfreeSkb struct {
	Common    processapi.MsgCommon `align:"common"`
	Calltrace MsgCalltrace         `align:"calltrace"`
	Tuple     MsgIPv4Tuple         `align:"tuple"`
}

type StackAddr struct {
	Addr   uint64
	Symbol string
}

type MsgKfreeSkbUnix struct {
	Common    processapi.MsgCommon
	Calltrace []StackAddr
	Tuple     vtuple.Impl
}
