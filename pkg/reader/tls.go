package reader

import (
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	api "github.com/isovalent/hubble-fgs/pkg/api/tlsapi"
	"github.com/isovalent/hubble-fgs/pkg/reader/network"
	"github.com/sirupsen/logrus"
	"github.com/yalue/native_endian"
)

func GetTLSSession(flv *api.FLV64) (s string) {
	session, _ := flv.Bytes()
	//       ^ TODO handle truncation?
	return hex.EncodeToString(session)
}

func GetTLSAlertLevel(level uint8) string {
	switch level {
	case 0x00:
		return ""
	case 0x01:
		return "warning"
	case 0x02:
		return "fatal"
	default:
		return fmt.Sprintf("0x%x", level)
	}
}

func GetTLSAlertDescription(description uint8) string {
	switch description {
	case 0x0:
		return ""
	case 0x28:
		return "handshake_failure"
	default:
		return fmt.Sprintf("0x%x", description)
	}
}

func GetTLSAlert(level uint8, description uint8) string {
	var s []string

	if level == 0 {
		return ""
	}
	s = append(s, GetTLSAlertLevel(level))
	s = append(s, GetTLSAlertDescription(description))
	return strings.Join(s, " ")
}

func GetTLSFlags(flags uint32) string {
	var s []string

	if (flags & api.TlsFlagCopyError) != 0 {
		s = append(s, "CopyError")
	}
	if (flags & api.TlsFlagMaxTlvs) != 0 {
		s = append(s, "MaxTLVError")
	}
	if (flags & api.TlsFlagFrameTooLarge) != 0 {
		s = append(s, "FrameTooLarge")
	}
	if (flags & api.TlsFlagHelloMsgMiss) != 0 {
		s = append(s, "HelloMsgMiss")
	}
	if (flags & api.TlsFlagHandshakeMsgMiss) != 0 {
		s = append(s, "HandshakeMsgMiss")
	}
	if (flags & api.TlsFlagCipherError) != 0 {
		s = append(s, "CipherError")
	}
	if (flags & api.TlsFlagCipherTooLarge) != 0 {
		s = append(s, "CipherTooLarge")
	}
	if (flags & api.TlsFlagCompressionError) != 0 {
		s = append(s, "CompressionError")
	}
	if (flags & api.TlsFlagCompressionTooLarge) != 0 {
		s = append(s, "CompressionTooLarge")
	}
	if (flags & api.TlsFlagExtError) != 0 {
		s = append(s, "ExtError")
	}
	if (flags & api.TlsFlagExtError) != 0 {
		s = append(s, "ExtError")
	}
	if (flags & api.TlsFlagExtTooLarge) != 0 {
		s = append(s, "ExtTooLarge")
	}
	if (flags & api.TlsFlagVersion) != 0 {
		s = append(s, "ExtVersion")
	}
	return strings.Join(s, " ")
}

func GetTLSVersion(version uint16) string {
	switch version {
	case api.TLSVersion13:
		return "TLS1.3"
	case api.TLSVersion12:
		return "TLS1.2"
	case api.TLSVersion11:
		return "TLS1.1"
	case api.TLSVersion10:
		return "TLS1.0"
	case api.TLSNone:
		return ""
	default:
		return "unknown(" + strconv.FormatUint(uint64(version), 10) + ")"
	}
}

func GetTLSSNI(sni [api.SNI_BUFFER_SIZE]byte) (string, string) {
	typeSNI := "unknown"
	switch sni[2] {
	case 0:
		typeSNI = "host_name"
	}
	nameLength := binary.BigEndian.Uint16(sni[3:5])
	if nameLength > api.SNI_BUFFER_SIZE-5 {
		nameLength = api.SNI_BUFFER_SIZE - 5
	}
	return typeSNI, string(sni[5 : 5+nameLength])
}

func GetTLSSupportedVersions(flv *api.FLV16, hasLength bool) string {
	var s []string
	vers, _ := flv.Bytes()
	//    ^ TODO handle truncated versions?

	if len(vers) < 2 {
		return ""
	} else if hasLength {
		end := int(vers[0]) + 1
		if end > len(vers) {
			end = len(vers)
		}
		vers = vers[1:end]
	} else {
		// serverHello supported versions extensions only has the
		// single entry with the the negotiated version. And does
		// not have a length field.
		vers = vers[0:2]
	}

	for i := 0; i <= len(vers)-2; i += 2 {
		t := native_endian.NativeEndian().Uint16(vers[i : i+2])
		s = append(s, GetTLSVersion(t))
	}
	return strings.Join(s, " ")
}

//func GetTLSRdns(rdns []byte) []string {
//	set := rdns[0]
//	setSize := rdns[1]
//
//	jj
//}

func defragHandshake(fragments []byte) ([]byte, uint32) {
	handshake := make([]byte, 0, len(fragments))

	for len(fragments) >= 5 {
		// TLS record header: [ type 8b | version 16b | length 16b ]
		typ := fragments[0]
		if typ != 22 {
			return nil, api.TlsCertificateErrorBadHeader
		}
		length := int(fragments[3])<<8 | int(fragments[4])
		fragments = fragments[5:]

		if len(fragments) < length {
			return nil, api.TlsCertificateErrorCertPartial
		}

		handshake = append(handshake, fragments[:length]...)
		fragments = fragments[length:]
	}

	if len(fragments) > 0 {
		return nil, api.TlsCertificateErrorCertPartial
	}

	return handshake, 0
}

func GetTLSCertificateString(fragments []byte) ([]string, uint32) {
	cert, code := defragHandshake(fragments)
	if code != 0 {
		return nil, code
	}
	if len(cert) < 6 {
		return nil, api.TlsCertificateErrorCertPartial
	}

	// Header: [ type 8b | length 24b | certs length 24b ]
	handshakeType := cert[0]
	if handshakeType != 11 {
		return nil, api.TlsCertificateErrorBadHeader
	}
	// Jump type + handshake length and parse the certificates length.
	cert = cert[4:]

	// Length of all certificates
	length := int(cert[0])<<16 | int(cert[1])<<8 | int(cert[2])
	cert = cert[3 : 3+length]

	var certSubjects []string

	for len(cert) > 3 {
		length = int(cert[0])<<16 | int(cert[1])<<8 | int(cert[2])

		if len(cert) < length {
			return certSubjects, api.TlsCertificateErrorCertPartial
		}

		certificate := cert[3 : 3+length]
		cert = cert[3+length:]

		parsedCert, err := x509.ParseCertificate(certificate)
		if err != nil {
			return certSubjects, api.TlsCertificateErrorParseX509
		}

		subjectRsdn := parsedCert.Subject.ToRDNSequence()
		certSubjects = append(certSubjects, subjectRsdn.String())
	}
	return certSubjects, 0
}

func ObserverTLSPrinter(msg *api.MsgTLSEventUnix, log logrus.FieldLogger) {
	op := msg.Common.Op
	typeSNI, nameSNI := GetTLSSNI(msg.ClientHello.SNI.Value)

	log.WithFields(logrus.Fields{
		"op":                           ops.OpCode(op).String(),
		"saddr":                        network.GetIP(msg.Tuple.SAddr, op).String(),
		"sport":                        network.GetSport(msg.Tuple.SPort),
		"dport":                        msg.Tuple.DPort,
		"daddr":                        network.GetIP(msg.Tuple.DAddr, op).String(),
		"Client-TLS-Version":           GetTLSVersion(msg.ClientHello.Version),
		"Server-TLS-Version":           GetTLSVersion(msg.ServerHello.Version),
		"SNI-Type":                     typeSNI,
		"SNI-Name":                     nameSNI,
		"Client-TLS-SupportedVersions": GetTLSSupportedVersions(&msg.ClientHello.SupportedVersions, true),
		"Server-TLS-SupportedVersions": GetTLSSupportedVersions(&msg.ServerHello.SupportedVersions, false),
		"cipher":                       GetTLSCiphers(&msg.ServerHello.Cipher),
	}).Warn()
}
