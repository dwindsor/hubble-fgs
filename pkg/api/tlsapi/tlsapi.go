package tlsapi

import (
	"fmt"

	"github.com/isovalent/hubble-fgs/pkg/api/processapi"
)

const (
	SNI_BUFFER_SIZE = 64
)

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

type MsgTLSIPv4 struct {
	SAddr     uint32
	DAddr     uint32
	DPort     uint16
	SPort     uint16
	Remaining uint32
	Uid       uint64
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


